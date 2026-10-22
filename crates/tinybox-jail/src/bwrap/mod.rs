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
//! namespaces and a private filesystem view, with the host *network* shared and
//! no seccomp. That is more than the plain `Process` doc describes and less than
//! `Kernel`; do not read it as "same process table". `Process` with `--disable-userns` support (bubblewrap
//! 0.8+), `None` without it. [`JailBackend::isolation_for`] reaches
//! [`IsolationLevel::Kernel`] only for a jail that denies network (a new net
//! namespace). With `allow_net` the host network namespace is shared, so host
//! loopback services and abstract sockets are reachable. Hosts must ask
//! [`JailBackend::is_suitable_for_untrusted_jail`]; the per-backend
//! `is_suitable_for_untrusted_code` is false by construction. `Kernel` here
//! means separate pid, mount, user, ipc and uts (and net) namespaces: it does
//! not imply seccomp or resource limits.
//!
//! # Known gaps (not closed in this backend)
//!
//! - No seccomp filter: `keyctl` (the user's kernel keyrings), `ptrace`,
//!   `bpf`, `io_uring` and similar syscalls remain reachable. A filter needs a
//!   file descriptor handed to `bwrap --seccomp`; the launcher could carry one,
//!   but a vetted BPF program is not part of this change.
//! - No CPU, memory or pid limits (`tinybox-linux` offers them through a
//!   `systemd-run` scope; not wired here).
//! - Check-then-use gap on nested grants: the symlink check on a grant inside a
//!   writable directory (`reject_symlinked_grants`) runs before `bwrap` binds
//!   the path, so a program that is already running in another session could
//!   swap a directory for a symlink in between. Closing it needs `O_PATH`
//!   descriptors opened with `openat2(RESOLVE_NO_SYMLINKS)` and
//!   `--bind-fd`/`--ro-bind-fd` (bubblewrap 0.10+); that is follow-up work.
//!   The window is only open while another sandbox with write access to the
//!   same tree is running.
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

    /// Test constructor that skips the probe, for fake launchers.
    #[cfg(test)]
    fn unverified(program: impl Into<PathBuf>, disable_userns: bool) -> Self {
        Self {
            verified: Some(Verified {
                program: program.into(),
                disable_userns,
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
fn verify(program: &Path) -> Option<Verified> {
    for disable_userns in [true, false] {
        if probe(program, disable_userns) {
            return Some(Verified {
                program: program.to_path_buf(),
                disable_userns,
            });
        }
    }
    None
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
    let Ok(argv) = args::jail_args(&jail, None, args::Options { disable_userns }) else {
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
    let out = launcher::command(shell, program, &file, "/bin/sh".as_ref(), &check)
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
    let mut argv = args::jail_args(
        jail,
        cmd.get_current_dir(),
        args::Options {
            disable_userns: verified.disable_userns,
        },
    )?;
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
    let launcher = launcher::command(
        shell,
        &verified.program,
        &file,
        cmd.get_program(),
        &program_args,
    );
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
