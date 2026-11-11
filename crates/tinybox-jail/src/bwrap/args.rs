//! Pure construction of the `bwrap` command line for a [`Jail`].
//!
//! What a sandbox binds and unshares *is* the security boundary, so every
//! decision here is a value a test can assert on. The only I/O is metadata
//! reads (is a baseline path a symlink, is a denied path a directory).
//!
//! # Mount model
//!
//! Baseline system paths and the jail's grants are one list of mounts. They are
//! emitted shallowest path first so a nested read-only grant lands on top of
//! the writable grant that contains it (a later mount wins). `deny_read` is
//! applied to that whole list, baseline included: a mount at or below a denied
//! path is dropped, and a denied path inside a surviving mount is masked.

use std::ffi::OsString;
use std::io;
use std::os::fd::{OwnedFd, RawFd};
use std::path::{Path, PathBuf};

use crate::jail::Jail;

/// System directories bound read-only (or re-created as symlinks) so a shell,
/// the dynamic loader and the C library can start. Missing entries are skipped.
pub(super) const SYSTEM_DIRS: &[&str] = &[
    "/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32",
];

/// The few `/etc` entries ordinary programs need (identity, name resolution,
/// TLS roots, the loader cache). Deliberately not all of `/etc`: that would
/// expose host keys and credentials the user can read.
pub(super) const ETC_ENTRIES: &[&str] = &[
    "/etc/passwd",
    "/etc/group",
    "/etc/hosts",
    "/etc/nsswitch.conf",
    "/etc/resolv.conf",
    "/etc/localtime",
    "/etc/ld.so.cache",
    "/etc/ld.so.conf",
    "/etc/ld.so.conf.d",
    "/etc/alternatives",
    "/etc/ssl",
    "/etc/ca-certificates",
    "/etc/pki",
];

/// Switches that depend on the `bwrap` build or the host, decided by the probe.
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct Options {
    /// Pass `--disable-userns` (bubblewrap 0.8+): the child cannot create
    /// nested user namespaces, which closes the usual escape route to a
    /// capability-bearing namespace.
    pub disable_userns: bool,
    /// Bind the jail's grants from descriptors (`--bind-fd`/`--ro-bind-fd`)
    /// opened here, instead of by path (see [`jail_args_with_fds`]).
    pub bind_fds: bool,
}

/// The first descriptor a grant is handed to `bwrap` on; the launcher keeps
/// this one and the ones after it open.
pub(super) const FIRST_GRANT_FD: RawFd = 10;

/// A `bwrap` argument list, plus the descriptors it binds grants from, each
/// with the number the child must see it on.
#[derive(Debug, Default)]
pub(super) struct JailArgs {
    pub argv: Vec<OsString>,
    pub fds: Vec<(OwnedFd, RawFd)>,
}

#[derive(Debug)]
enum Kind {
    /// A symlink created inside the sandbox root (merged-`/usr` layouts).
    Symlink(PathBuf),
    Bind {
        writable: bool,
    },
}

#[derive(Debug)]
struct Mount {
    path: PathBuf,
    kind: Kind,
    /// One of the jail's own grants, not a baseline system path.
    grant: bool,
}

impl Mount {
    fn is_bind(&self) -> bool {
        matches!(self.kind, Kind::Bind { .. })
    }

    fn writable(&self) -> bool {
        matches!(self.kind, Kind::Bind { writable: true })
    }

    /// Sort key: shallow first; at equal depth a read-only mount goes last so
    /// it wins over a writable one on the same path.
    fn order(&self) -> (usize, bool) {
        (self.path.components().count(), !self.writable())
    }
}

fn os(s: &str) -> OsString {
    s.into()
}

/// Refuses a path the private-mount guard could be talked around with: only
/// absolute paths without `..` are meaningful here (`/usr/../tmp` is `/tmp`).
fn require_clean(path: &Path) -> io::Result<()> {
    use std::os::unix::ffi::OsStrExt as _;
    if path.is_absolute()
        && !path.as_os_str().as_bytes().contains(&0)
        && !path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        format!(
            "jail path {} must be absolute, without `..` components or NUL bytes",
            path.display()
        ),
    ))
}

/// Whether a grant would replace one of the sandbox's private mounts.
fn replaces_private_mount(path: &Path) -> bool {
    path == Path::new("/")
        || path == Path::new("/tmp")
        || path.starts_with("/proc")
        || path.starts_with("/dev")
}

/// The baseline mounts: system directories (or their symlinks) and the short
/// `/etc` allow-list.
fn baseline_mounts() -> Vec<Mount> {
    let mut mounts: Vec<Mount> = Vec::new();
    for dir in SYSTEM_DIRS {
        let path = PathBuf::from(dir);
        mounts.push(match std::fs::read_link(&path) {
            Ok(target) => Mount {
                path,
                kind: Kind::Symlink(target),
                grant: false,
            },
            Err(_) => Mount {
                path,
                kind: Kind::Bind { writable: false },
                grant: false,
            },
        });
    }
    for entry in ETC_ENTRIES {
        mounts.push(Mount {
            path: PathBuf::from(entry),
            kind: Kind::Bind { writable: false },
            grant: false,
        });
    }

    mounts
}

/// Everything after the `bwrap` program name and before the `--` separator.
///
/// - new user, pid, ipc, uts (and cgroup where supported) namespaces; a new
///   network namespace unless `jail.allow_net`; optionally `--disable-userns`;
/// - `--die-with-parent` and `--new-session`;
/// - a private `/proc`, `/dev` and `/tmp`;
/// - baseline system paths and the root, `read_write` and `read_only` grants,
///   shallowest first (see the module docs);
/// - `deny_read` subtracted last.
///
/// # Errors
/// - `NotFound` when the root, a `read_write` grant, or a `deny_read` path does
///   not exist;
/// - `InvalidInput` for a relative path or one containing `..`, for a symlink
///   below a writable grant that a nested grant goes through, for a grant that is `/`, `/tmp`, or at or under `/proc` or
///   `/dev` (it would replace a private mount and expose the host's), and for
///   a `deny_read` entry nested more than one level inside a writable mount
///   (the child could rename a parent directory and walk around the mask).
pub(super) fn jail_args(
    jail: &Jail,
    cwd: Option<&Path>,
    options: Options,
) -> io::Result<Vec<OsString>> {
    let paths_only = Options {
        bind_fds: false,
        ..options
    };
    jail_args_with_fds(jail, cwd, paths_only).map(|args| args.argv)
}

/// [`jail_args`], with the grants bound from descriptors when
/// `options.bind_fds` is set.
///
/// A path check followed by `bwrap --bind PATH` leaves a window in which a
/// program with write access to a grant's parent can swap a directory for a
/// symlink. Here each grant is opened once, as an `O_PATH` descriptor, and
/// `bwrap` binds that descriptor, so what was checked is what is mounted. A
/// grant inside an already-opened grant is opened relative to it with
/// `RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH`, so no symlink on that stretch is
/// followed (another sandbox may be able to write there even when this one
/// cannot); any other grant is opened by its declared path, whose ancestors
/// the host controls. A missing read-only grant is skipped, as `--ro-bind-try`
/// skips it.
///
/// # Errors
/// As [`jail_args`], plus the error from opening a grant (`ELOOP` when a
/// symlink was planted inside a writable grant).
pub(super) fn jail_args_with_fds(
    jail: &Jail,
    cwd: Option<&Path>,
    options: Options,
) -> io::Result<JailArgs> {
    check_paths(jail, cwd)?;
    let mut mounts = baseline_mounts();
    for (path, writable) in std::iter::once((&jail.root, true))
        .chain(jail.read_write.iter().map(|p| (p, true)))
        .chain(jail.read_only.iter().map(|p| (p, false)))
    {
        if replaces_private_mount(path) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "jail grant {} would replace a private sandbox mount (/, /tmp, /proc, /dev)",
                    path.display()
                ),
            ));
        }
        if writable && !path.exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("jail path {} does not exist", path.display()),
            ));
        }
        mounts.push(Mount {
            path: path.clone(),
            kind: Kind::Bind { writable },
            grant: true,
        });
    }

    // A denial spelled through a baseline symlink (`/bin/sh`) also denies where
    // the link points (`/usr/bin/sh`): the sandbox mounts the target, not the
    // link.
    let denied = effective_denials(&jail.deny_read, &mounts);
    // A mount at or below a denied path is never mounted.
    mounts.retain(|m| !denied.iter().any(|deny| m.path.starts_with(deny)));
    mounts.sort_by_key(Mount::order);

    let mut argv: Vec<OsString> = ["--unshare-user", "--unshare-pid", "--unshare-ipc"]
        .into_iter()
        .map(os)
        .collect();
    argv.extend(["--unshare-uts", "--unshare-cgroup-try"].map(os));
    if !jail.allow_net {
        argv.push(os("--unshare-net"));
    }
    if options.disable_userns {
        argv.push(os("--disable-userns"));
    }
    argv.extend(["--die-with-parent", "--new-session"].map(os));

    // `/tmp` first: a grant living under it (a scratch root) is bound on top.
    for (flag, path) in [("--proc", "/proc"), ("--dev", "/dev"), ("--tmpfs", "/tmp")] {
        argv.extend([os(flag), os(path)]);
    }

    let mut fds = GrantFds::default();
    for mount in &mounts {
        match &mount.kind {
            Kind::Symlink(target) => argv.extend([
                os("--symlink"),
                target.clone().into_os_string(),
                mount.path.clone().into_os_string(),
            ]),
            Kind::Bind { writable } if options.bind_fds && mount.grant => {
                let Some(fd) = fds.open(&mount.path, *writable)? else {
                    continue;
                };
                argv.extend([
                    os(if *writable {
                        "--bind-fd"
                    } else {
                        "--ro-bind-fd"
                    }),
                    fd.to_string().into(),
                    mount.path.clone().into_os_string(),
                ]);
            }
            Kind::Bind { writable } => argv.extend([
                os(if *writable { "--bind" } else { "--ro-bind-try" }),
                mount.path.clone().into_os_string(),
                mount.path.clone().into_os_string(),
            ]),
        }
    }

    argv.extend(deny_masks(&denied, &mounts)?);

    argv.extend([
        os("--chdir"),
        cwd.unwrap_or(&jail.root).as_os_str().to_os_string(),
    ]);
    Ok(JailArgs {
        argv,
        fds: fds.into_mappings(),
    })
}

/// Every path is absolute and clean, and no grant inside a writable one
/// reaches its target through a symlink the jailed program could have planted.
fn check_paths(jail: &Jail, cwd: Option<&Path>) -> io::Result<()> {
    for path in std::iter::once(&jail.root)
        .chain(&jail.read_write)
        .chain(&jail.read_only)
        .chain(&jail.deny_read)
        .map(PathBuf::as_path)
        .chain(cwd)
    {
        require_clean(path)?;
    }
    let writable: Vec<&Path> = std::iter::once(&jail.root)
        .chain(&jail.read_write)
        .map(PathBuf::as_path)
        .collect();
    let nested: Vec<&Path> = jail
        .read_only
        .iter()
        .chain(&jail.read_write)
        .map(PathBuf::as_path)
        .collect();
    crate::jail::reject_symlinked_grants(&writable, &nested)
}

/// The grant descriptors opened so far, shallowest first, numbered from
/// [`FIRST_GRANT_FD`].
#[derive(Default)]
struct GrantFds {
    opened: Vec<(PathBuf, OwnedFd)>,
}

impl GrantFds {
    /// Opens `path` and returns the number the child will see it on, or
    /// `None` for a missing read-only grant.
    fn open(&mut self, path: &Path, writable: bool) -> io::Result<Option<RawFd>> {
        use nix::fcntl::{OFlag, OpenHow, ResolveFlag};
        let flags = OFlag::O_PATH | OFlag::O_CLOEXEC;
        // The deepest grant already opened that contains this one.
        let parent = self
            .opened
            .iter()
            .filter(|(dir, _)| path.starts_with(dir) && path != dir)
            .max_by_key(|(dir, _)| dir.components().count());
        let opened = match parent {
            Some((dir, fd)) => nix::fcntl::openat2(
                fd,
                path.strip_prefix(dir).map_err(io::Error::other)?,
                OpenHow::new()
                    .flags(flags)
                    .resolve(ResolveFlag::RESOLVE_NO_SYMLINKS | ResolveFlag::RESOLVE_BENEATH),
            ),
            None => nix::fcntl::openat2(nix::fcntl::AT_FDCWD, path, OpenHow::new().flags(flags)),
        };
        let fd = match opened {
            Ok(fd) => fd,
            Err(nix::errno::Errno::ENOENT) if !writable => return Ok(None),
            Err(errno) => {
                return Err(io::Error::new(
                    io::Error::from(errno).kind(),
                    format!("cannot open jail grant {}: {errno}", path.display()),
                ));
            }
        };
        let number =
            FIRST_GRANT_FD + RawFd::try_from(self.opened.len()).map_err(io::Error::other)?;
        self.opened.push((path.to_path_buf(), fd));
        Ok(Some(number))
    }

    fn into_mappings(self) -> Vec<(OwnedFd, RawFd)> {
        self.opened
            .into_iter()
            .zip(FIRST_GRANT_FD..)
            .map(|((_, fd), number)| (fd, number))
            .collect()
    }
}

/// `deny_read` plus, for each entry under a baseline symlink, the same path
/// under the link's target.
fn effective_denials(deny_read: &[PathBuf], mounts: &[Mount]) -> Vec<PathBuf> {
    let mut denied = deny_read.to_vec();
    for deny in deny_read {
        for mount in mounts {
            let Kind::Symlink(target) = &mount.kind else {
                continue;
            };
            let Ok(rest) = deny.strip_prefix(&mount.path) else {
                continue;
            };
            let base = if target.is_absolute() {
                target.clone()
            } else {
                mount
                    .path
                    .parent()
                    .map_or_else(|| target.clone(), |parent| parent.join(target))
            };
            denied.push(base.join(rest));
        }
    }
    denied.sort();
    denied.dedup();
    denied
}

/// Arguments that subtract `deny_read` from the surviving mounts.
fn deny_masks(denied: &[PathBuf], mounts: &[Mount]) -> io::Result<Vec<OsString>> {
    let mut argv: Vec<OsString> = Vec::new();
    for deny in denied {
        // The deepest surviving mount that holds the denied path decides.
        let Some(holder) = mounts
            .iter()
            .filter(|m| m.is_bind() && deny.starts_with(&m.path))
            .max_by_key(|m| m.path.components().count())
        else {
            continue;
        };
        if holder.writable()
            && let Some(error) = crate::jail::nested_denial(deny, &holder.path)
        {
            return Err(error);
        }
        match std::fs::metadata(deny) {
            Ok(meta) if meta.is_dir() => {
                argv.extend([os("--tmpfs"), deny.clone().into_os_string()]);
            }
            Ok(_) => argv.extend([
                os("--ro-bind"),
                os("/dev/null"),
                deny.clone().into_os_string(),
            ]),
            // Bubblewrap's `--tmpfs` creates a missing destination on the host
            // before mounting it. Refuse prospective denials rather than
            // mutating a granted host directory or preventing that path from
            // later being created as a file.
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!(
                        "deny_read path {} must exist before starting the jail",
                        deny.display()
                    ),
                ));
            }
            Err(error) => return Err(error),
        }
    }
    Ok(argv)
}

#[cfg(test)]
#[path = "args_tests.rs"]
mod tests;
