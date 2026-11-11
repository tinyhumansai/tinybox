//! Linux bubblewrap backend: namespace isolation for untrusted code.
//!
//! [`BubblewrapBackend`] runs the command under `bwrap` with fresh user, pid,
//! ipc and uts namespaces (and a net namespace unless the jail allows
//! network). The child sees a private mount tree holding only the baseline
//! system paths plus the jail's grants, so it cannot read an ungranted path,
//! cannot see host processes, cannot create nested user namespaces
//! (`--disable-userns`), and dies with its parent.
//!
//! # Choosing `bwrap`
//!
//! `bwrap` is never looked up on `PATH`. Only `/usr/bin/bwrap`,
//! `/usr/local/bin/bwrap` and `/bin/bwrap` are considered, and only when owned
//! by root and not group- or other-writable. [`BubblewrapBackend::with_program`]
//! lets a host name another binary: it **skips that ownership check**, so the
//! host is vouching for the path. Either way the binary must pass a probe, run
//! once per process: a sandbox that starts, in which a host-only file is
//! invisible and the pid namespace differs from the parent's. The probe is a
//! sanity check that the thing isolates, not an authenticity check: a
//! malicious `bwrap` that prints the expected answer passes it.
//!
//! # Environment and credentials
//!
//! Nothing the caller sets reaches a host-side process. A small launcher shell
//! runs with an empty environment, and the whole `bwrap` argument list,
//! including every `--setenv NAME value`, travels in a private file read
//! through `bwrap --args 9` (see `launcher.rs`). So a token in the command's
//! environment is in neither `/proc/<pid>/cmdline` (world-readable) nor in the
//! environment of a host process, and `LD_PRELOAD` and similar loader
//! variables take effect only inside the sandbox. The file is mode 0600 in a
//! fresh 0700 directory and is deleted by the launcher as soon as it is open.
//! If the launcher cannot start at all the file is removed on the error path.
//!
//! # What is claimed
//!
//! [`JailBackend::isolation`] is the **minimum over every configuration the
//! backend accepts**. It is reported as `Process`, the closest defined level
//! below `Kernel`, but note what it means here: pid, mount, user and ipc
//! namespaces, a private filesystem view and the seccomp deny list, with the
//! host *network* shared. That is more than the plain `Process` doc describes and less than
//! `Kernel`; do not read it as "same process table". `Process` with `--disable-userns` support (bubblewrap
//! 0.8+), `None` without it. [`JailBackend::isolation_for`] reaches
//! [`IsolationLevel::Kernel`] only for a jail that denies network (a new net
//! namespace). With `allow_net` the host network namespace is shared, so host
//! loopback services and abstract sockets are reachable. Hosts must ask
//! [`JailBackend::is_suitable_for_untrusted_jail`]; the per-backend
//! `is_suitable_for_untrusted_code` is false by construction. `Kernel` here
//! means separate pid, mount, user, ipc and uts (and net) namespaces plus that
//! deny list: it does not imply resource limits.
//!
//! # Seccomp
//!
//! Every jail starts under a seccomp deny list (`seccomp.rs`): kernel keyrings,
//! other processes' memory, `bpf`/`perf`/`userfaultfd`/`io_uring`, every mount
//! call, `setns` and namespace-creating `clone`/`unshare`, file handles,
//! modules, `kexec`, reboot, host clock, swap and syslog, terminal injection
//! ioctls, and the x86 legacy calls. Denied calls fail with `EPERM` (`clone3`
//! with `ENOSYS`, so the C library falls back to `clone`). `ptrace` stays
//! allowed on Linux 4.8 and later, confined to the jail's pid namespace. A
//! `bwrap` without `--add-seccomp-fd`, or an architecture other than `x86_64`
//! and `aarch64`, leaves the backend unavailable rather than unfiltered.
//!
//! # Known gaps (not closed in this backend)
//!
//! - No CPU, memory or pid limits (`tinybox-linux` offers them through a
//!   `systemd-run` scope; not wired here).
//! - Check-then-use gap on nested grants, **only where `bwrap` lacks
//!   `--bind-fd` or the kernel lacks `openat2` (before Linux 5.6)**. Then the
//!   symlink check on a grant inside a writable directory
//!   (`reject_symlinked_grants`) runs before `bwrap` binds the path, so a
//!   program already running in another session could swap a directory for a
//!   symlink in between. Otherwise each grant is opened once as an `O_PATH`
//!   descriptor, a nested one beneath its parent's with
//!   `RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH`, and bound with
//!   `--bind-fd`/`--ro-bind-fd`, so what was checked is what is mounted.
//!   [`BubblewrapBackend::binds_by_descriptor`] reports which is in effect.
//! - `deny_read` paths must exist when the jail starts: a path created later
//!   under a mounted grant is **not** protected. One nested more than a level
//!   inside a writable grant is refused.
//! - Landlock is not layered inside: the kernel denies `mount` and
//!   `pivot_root` to a Landlock-restricted thread, which would break `bwrap`'s
//!   own setup.
//! - Subprocess denial is not enforced and is refused.
//!
//! # Other behaviour
//!
//! Stdio configured on the original `Command` is not recoverable from `std`
//! (as with Seatbelt); use `spawn_captured` for pipes. Descriptors above 2 that
//! the host left inheritable are closed by the launcher after it starts,
//! including ones opened by another thread at the moment of the spawn. Under
//! `dash` (no `bash` installed) a descriptor above 9 cannot be closed and the
//! sandbox fails to start rather than leak it.

use std::ffi::OsString;
use std::io;
use std::os::unix::fs::MetadataExt as _;
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;

use tinybox_core::{Constraint, ConstraintSupport, Enforcement, IsolationLevel};

use crate::jail::{Jail, JailBackend};

mod args;
mod launcher;
mod seccomp;

/// Backend name reported by [`BubblewrapBackend`].
pub const BWRAP_BACKEND_NAME: &str = "bubblewrap";

/// Where a trusted `bwrap` may live.
const TRUSTED_PATHS: &[&str] = &["/usr/bin/bwrap", "/usr/local/bin/bwrap", "/bin/bwrap"];

/// One probe per process for the default (trusted-path) `bwrap`.
static DEFAULT_PROBE: OnceLock<Option<Verified>> = OnceLock::new();

/// A `bwrap` shown to create a sandbox, and what it supports.
#[derive(Debug, Clone)]
struct Verified {
    program: PathBuf,
    disable_userns: bool,
    /// `bwrap` lists `--bind-fd` and the kernel has `openat2`: grants are
    /// bound from descriptors rather than re-resolved by path.
    bind_fds: bool,
    /// The compiled seccomp filters every jail starts under (see `seccomp`).
    seccomp: Vec<Vec<u8>>,
}

/// Bubblewrap (`bwrap`) namespace jail backend.
#[derive(Debug, Clone)]
pub struct BubblewrapBackend {
    verified: Option<Verified>,
}

impl Default for BubblewrapBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl BubblewrapBackend {
    /// Finds a trusted `bwrap` and probes it once per process.
    #[must_use]
    pub fn new() -> Self {
        let verified = DEFAULT_PROBE
            .get_or_init(|| {
                let found = TRUSTED_PATHS
                    .iter()
                    .map(PathBuf::from)
                    .find(|path| is_trusted_binary(path));
                let verified = found.and_then(|path| verify(&path));
                if verified.is_none() {
                    log::debug!(
                        "[cwd_jail:bwrap] unavailable: {}",
                        tinybox_linux::NamespaceProbe::detect()
                            .problem()
                            .unwrap_or_else(|| "no trusted bwrap passed the probe".to_owned())
                    );
                }
                verified
            })
            .clone();
        Self { verified }
    }

    /// Uses an explicit `bwrap` binary chosen by the host. The ownership check
    /// is skipped (the host vouches for the path) but the isolation probe is
    /// not. Unavailable if the probe fails.
    #[must_use]
    pub fn with_program(program: impl Into<PathBuf>) -> Self {
        Self {
            verified: verify(&program.into()),
        }
    }

    /// The `bwrap` binary this backend launches, when available.
    #[must_use]
    pub fn program(&self) -> Option<&Path> {
        self.verified.as_ref().map(|v| v.program.as_path())
    }

    /// Whether grants are bound from descriptors opened at spawn
    /// (`--bind-fd`, bubblewrap 0.9+ on Linux 5.6+), which closes the
    /// check-then-use gap on nested grants. When false they are bound by path
    /// and the gap stays open (see the module docs).
    #[must_use]
    pub fn binds_by_descriptor(&self) -> bool {
        self.verified.as_ref().is_some_and(|v| v.bind_fds)
    }

    /// Whether jails start under the seccomp deny list. True whenever the
    /// backend is available: a `bwrap` that cannot load it is not used.
    #[must_use]
    pub fn installs_seccomp(&self) -> bool {
        self.verified
            .as_ref()
            .is_some_and(|v| !v.seccomp.is_empty())
    }

    /// Test constructor that skips the probe, for fake launchers.
    #[cfg(test)]
    fn unverified(program: impl Into<PathBuf>, disable_userns: bool) -> Self {
        Self {
            verified: Some(Verified {
                program: program.into(),
                disable_userns,
                bind_fds: false,
                seccomp: Vec::new(),
            }),
        }
    }
}

/// Whether `path` is a regular executable owned by root and writable by no one
/// else.
fn is_trusted_binary(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|meta| {
        meta.is_file() && meta.uid() == 0 && meta.mode() & 0o022 == 0 && meta.mode() & 0o111 != 0
    })
}

/// Runs throwaway sandboxes to learn whether `program` really isolates, and
/// whether it supports `--disable-userns`.
///
/// A `bwrap` that cannot install the seccomp filters (no `--add-seccomp-fd`,
/// or no filter for this architecture) is not used: a jail is refused rather
/// than started unfiltered.
fn verify(program: &Path) -> Option<Verified> {
    let seccomp = match seccomp_filters(program) {
        Ok(filters) => filters,
        Err(error) => {
            log::debug!("[cwd_jail:bwrap] unavailable: {error}");
            return None;
        }
    };
    for disable_userns in [true, false] {
        if probe(program, disable_userns) {
            return Some(Verified {
                program: program.to_path_buf(),
                disable_userns,
                bind_fds: supports_fd_binds(program),
                seccomp,
            });
        }
    }
    None
}

/// The filters for this kernel and architecture, if `program` can load them.
fn seccomp_filters(program: &Path) -> io::Result<Vec<Vec<u8>>> {
    if !help_lists(program, "--add-seccomp-fd") {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "{} cannot load seccomp filters (no --add-seccomp-fd); jails are refused",
                program.display()
            ),
        ));
    }
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease")?;
    let kernel = seccomp::kernel_version(&release).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unreadable kernel release {release:?}"),
        )
    })?;
    seccomp::filters(kernel)
}

/// Whether `program --help` names `flag` as an option.
fn help_lists(program: &Path, flag: &str) -> bool {
    Command::new(program)
        .arg("--help")
        .env_clear()
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .is_ok_and(|out| {
            String::from_utf8_lossy(&out.stdout)
                .split_whitespace()
                .any(|word| word == flag)
        })
}

/// Whether `program --help` lists `--bind-fd` (bubblewrap 0.9 does) and
/// `openat2` works on this kernel (Linux 5.6+).
fn supports_fd_binds(program: &Path) -> bool {
    let listed = help_lists(program, "--bind-fd");
    let openat2 = nix::fcntl::openat2(
        nix::fcntl::AT_FDCWD,
        "/",
        nix::fcntl::OpenHow::new().flags(nix::fcntl::OFlag::O_PATH | nix::fcntl::OFlag::O_CLOEXEC),
    )
    .is_ok();
    log::debug!(
        "[cwd_jail:bwrap] {} --bind-fd listed={listed} openat2={openat2}",
        program.display()
    );
    listed && openat2
}

fn probe(program: &Path, disable_userns: bool) -> bool {
    // A fresh, private, randomly named directory: never a predictable path
    // another user could pre-create or symlink.
    let Ok(dir) = private_probe_dir() else {
        return false;
    };
    let root = dir.join("root");
    let host_only = dir.join("host-only");
    let setup = std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&root)
        .and_then(|()| {
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&host_only)
                .map(drop)
        });
    let ok = setup.is_ok() && run_probe(program, disable_userns, &root, &host_only);
    let _ = std::fs::remove_dir_all(&dir);
    log::debug!(
        "[cwd_jail:bwrap] probe {} disable_userns={disable_userns} -> {ok}",
        program.display()
    );
    ok
}

/// `$TMPDIR/tinybox-bwrap-probe-<random>`, created mode 0700 with `create`
/// (which fails if the name exists).
fn private_probe_dir() -> io::Result<PathBuf> {
    let dir = std::env::temp_dir().join(format!("tinybox-bwrap-probe-{}", launcher::random_hex()?));
    std::fs::DirBuilder::new().mode(0o700).create(&dir)?;
    Ok(dir)
}

fn run_probe(program: &Path, disable_userns: bool, root: &Path, host_only: &Path) -> bool {
    let Ok(parent_pidns) = std::fs::read_link("/proc/self/ns/pid") else {
        return false;
    };
    let jail = Jail::new(root, "bwrap-probe").deny_net();
    let options = args::Options {
        disable_userns,
        ..args::Options::default()
    };
    let Ok(argv) = args::jail_args(&jail, None, options) else {
        return false;
    };
    let check: Vec<OsString> = [
        "-c",
        "test ! -e \"$1\" && test \"$(readlink /proc/self/ns/pid)\" != \"$2\" && echo isolated",
        "probe",
    ]
    .map(OsString::from)
    .into_iter()
    .chain([host_only.into(), parent_pidns.into()])
    .collect();
    // The same launcher path as a real spawn, so it is exercised too.
    let Ok(base) = launcher::base_dir(&[root], xdg_runtime_dir(), std::env::temp_dir()) else {
        return false;
    };
    let Ok(file) = launcher::ArgsFile::create(&argv, &base) else {
        return false;
    };
    let shell = launcher::pick_shell(|path| Path::new(path).is_file());
    // Positive evidence is required: a launcher that exits 0 without running
    // the check (`true`) must not pass.
    let out = launcher::command(shell, program, &file, 0, "/bin/sh".as_ref(), &check)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output();
    file.discard();
    out.is_ok_and(|out| out.status.success() && out.stdout == b"isolated\n")
}

/// `$XDG_RUNTIME_DIR` when it is an absolute path.
fn xdg_runtime_dir() -> Option<PathBuf> {
    std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|dir| dir.is_absolute())
}

/// A command ready to spawn, plus the argument file it will consume.
struct Prepared {
    launcher: Command,
    args: launcher::ArgsFile,
}

/// Rebuilds `cmd` as a launcher + `bwrap --args` invocation of the same
/// program.
///
/// The launcher command carries no environment and its own argv holds only
/// paths; the caller's variables and arguments live in the private args file.
fn prepare_command(verified: &Verified, jail: &Jail, cmd: &Command) -> io::Result<Prepared> {
    let args::JailArgs { mut argv, mut fds } = args::jail_args_with_fds(
        jail,
        cmd.get_current_dir(),
        args::Options {
            disable_userns: verified.disable_userns,
            bind_fds: verified.bind_fds,
        },
    )?;
    // Each filter on its own pipe, numbered after the grants. A filter is a
    // few kilobytes, well inside a pipe's buffer, so writing it before bwrap
    // reads cannot block.
    for filter in &verified.seccomp {
        let (reader, mut writer) = std::io::pipe()?;
        io::Write::write_all(&mut writer, filter)?;
        drop(writer);
        let number = args::FIRST_GRANT_FD + i32::try_from(fds.len()).map_err(io::Error::other)?;
        argv.extend(["--add-seccomp-fd".into(), number.to_string().into()]);
        fds.push((reader.into(), number));
    }
    argv.push("--clearenv".into());
    for (key, value) in cmd.get_envs() {
        if let Some(value) = value {
            argv.extend(["--setenv".into(), key.to_os_string(), value.to_os_string()]);
        }
    }

    let grants: Vec<&Path> = std::iter::once(&jail.root)
        .chain(&jail.read_write)
        .chain(&jail.read_only)
        .map(PathBuf::as_path)
        .collect();
    let base = launcher::base_dir(&grants, xdg_runtime_dir(), std::env::temp_dir())?;
    let file = launcher::ArgsFile::create(&argv, &base)?;
    let shell = launcher::pick_shell(|path| Path::new(path).is_file());
    let program_args: Vec<OsString> = cmd.get_args().map(OsString::from).collect();
    let mut launcher = launcher::command(
        shell,
        &verified.program,
        &file,
        fds.len(),
        cmd.get_program(),
        &program_args,
    );
    // Mapped onto 10, 11, … in the child only, after fork: never inheritable
    // in this process, where another thread could spawn concurrently.
    let mappings = fds
        .into_iter()
        .map(|(parent_fd, child_fd)| command_fds::FdMapping {
            parent_fd,
            child_fd,
        })
        .collect();
    command_fds::CommandFdExt::fd_mappings(&mut launcher, mappings)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    Ok(Prepared {
        launcher,
        args: file,
    })
}

impl JailBackend for BubblewrapBackend {
    fn carves_denials(&self) -> bool {
        true
    }

    fn name(&self) -> &'static str {
        BWRAP_BACKEND_NAME
    }

    fn is_available(&self) -> bool {
        self.verified.is_some()
    }

    fn constraint_support(&self) -> ConstraintSupport {
        if self.is_available() {
            ConstraintSupport::NONE
                .with(Constraint::Filesystem, Enforcement::Enforced)
                .with(Constraint::Network, Enforcement::Enforced)
        } else {
            ConstraintSupport::NONE
        }
    }

    fn isolation(&self) -> IsolationLevel {
        // The minimum over every accepted configuration: with `allow_net` the
        // host network namespace is shared. `Process` is the closest defined
        // level below `Kernel`.
        match &self.verified {
            Some(v) if v.disable_userns => IsolationLevel::Process,
            _ => IsolationLevel::None,
        }
    }

    fn isolation_for(&self, jail: &Jail) -> IsolationLevel {
        match self.isolation() {
            IsolationLevel::Process if !jail.allow_net => IsolationLevel::Kernel,
            level => level,
        }
    }

    fn spawn(&self, jail: &Jail, cmd: Command) -> io::Result<Child> {
        self.launch(jail, &cmd, false)
    }

    fn spawn_captured(&self, jail: &Jail, cmd: Command) -> io::Result<Child> {
        self.launch(jail, &cmd, true)
    }
}

impl BubblewrapBackend {
    /// Preflight, rebuild the command as `bwrap`, and spawn it. Pipes must be
    /// set on the wrapper, not the original command, which is discarded.
    fn launch(&self, jail: &Jail, cmd: &Command, captured: bool) -> io::Result<Child> {
        let Some(verified) = &self.verified else {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "bubblewrap is not available (no trusted working bwrap or user namespaces disabled)",
            ));
        };
        self.constraint_support()
            .require(self.name(), &jail.constraints())
            .map_err(|error| io::Error::new(io::ErrorKind::Unsupported, error))?;
        log::debug!("[cwd_jail:bwrap] spawning label={}", jail.label);
        let Prepared {
            launcher: mut wrapper,
            args,
        } = prepare_command(verified, jail, cmd)?;
        if captured {
            wrapper
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                // Own process group, as the Seatbelt backend does, so the host
                // can signal the whole sandbox.
                .process_group(0);
        }
        wrapper.spawn().inspect_err(|_| args.discard())
    }
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
