//! Linux backend: Landlock LSM (kernel 5.13+).
//!
//! Landlock restricts the *calling thread* and everything that thread later
//! forks. The usual way to confine a child is `CommandExt::pre_exec`, but that
//! is `unsafe` and this workspace forbids `unsafe_code`. Instead the ruleset is
//! applied to a short-lived dedicated thread and the command is spawned from
//! that thread: the child inherits the thread's Landlock domain (and
//! `no_new_privs`), the thread is discarded after the spawn, and the calling
//! thread and the rest of the process keep their full privileges. No unsafe
//! code is needed in this crate (the `landlock` crate owns the syscalls).
//!
//! # What the jail grants
//!
//! - `jail.root` and every `jail.read_write` path: read, write and execute.
//! - every `jail.read_only` path: read and execute.
//! - a fixed baseline so an ordinary shell can start at all: the system
//!   directories in [`SYSTEM_READ_PATHS`] (read and execute) and the harmless
//!   character devices in [`DEVICE_PATHS`] (read and write). Missing baseline
//!   paths are skipped.
//!
//! Everything else on the filesystem is denied, including the rest of the home
//! directory (`~/.ssh`, `~/.aws`, ...), `/proc` and `/sys`, and `/tmp`. A host
//! that wants a scratch directory grants it with `add_read_write`.
//!
//! Landlock does not gate the network or process creation, so `allow_net` and
//! `allow_subprocess` are not enforced by this backend.
//!
//! # Degrading on old kernels
//!
//! [`LandlockBackend::is_available`] probes the kernel. When Landlock is not
//! supported (kernel older than 5.13, or the LSM is not enabled) the backend
//! reports unavailable, [`crate::detect::pick_backend`] moves on, and `spawn`
//! returns `ErrorKind::Unsupported` without ever running the command
//! unconfined. A kernel that supports only older ABIs is handled best-effort:
//! rights the kernel does not know are dropped and a debug line says so.

use std::io;
use std::process::{Child, Command};

use super::jail::{Jail, JailBackend};

/// Backend name reported by [`LandlockBackend`].
pub const LANDLOCK_BACKEND_NAME: &str = "landlock";

/// System directories every jailed child may read and execute from, so that a
/// shell, the dynamic loader and the C library can start. Missing entries are
/// skipped.
pub const SYSTEM_READ_PATHS: &[&str] = &[
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/lib32",
    "/lib64",
    "/libx32",
    "/etc",
    // `/etc/resolv.conf` is a symlink into here on systemd-resolved hosts;
    // without it no name resolves.
    "/run/systemd/resolve",
];

/// Character devices every jailed child may read and write: shell
/// redirections to `/dev/null`, entropy, and the controlling terminal. Missing
/// entries are skipped.
pub const DEVICE_PATHS: &[&str] = &[
    "/dev/null",
    "/dev/zero",
    "/dev/full",
    "/dev/random",
    "/dev/urandom",
    "/dev/tty",
];

/// Landlock LSM backend (kernel 5.13+).
#[derive(Debug)]
pub struct LandlockBackend;

impl Default for LandlockBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl LandlockBackend {
    /// Creates the backend; availability is checked by `is_available`.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl JailBackend for LandlockBackend {
    fn name(&self) -> &'static str {
        LANDLOCK_BACKEND_NAME
    }

    fn is_available(&self) -> bool {
        imp::kernel_supports_landlock()
    }

    fn spawn(&self, jail: &Jail, cmd: Command) -> io::Result<Child> {
        imp::spawn(jail, cmd)
    }
}

#[cfg(feature = "landlock")]
mod imp {
    use std::io;
    use std::path::Path;
    use std::process::{Child, Command};

    use landlock::{
        AccessFs, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset, RulesetAttr,
        RulesetCreated, RulesetCreatedAttr, RulesetStatus,
    };

    use super::{DEVICE_PATHS, SYSTEM_READ_PATHS};
    use crate::jail::Jail;

    fn writes() -> landlock::BitFlags<AccessFs> {
        AccessFs::WriteFile
            | AccessFs::RemoveDir
            | AccessFs::RemoveFile
            | AccessFs::MakeChar
            | AccessFs::MakeDir
            | AccessFs::MakeReg
            | AccessFs::MakeSock
            | AccessFs::MakeFifo
            | AccessFs::MakeBlock
            | AccessFs::MakeSym
            | AccessFs::Refer
            | AccessFs::Truncate
    }

    fn reads() -> landlock::BitFlags<AccessFs> {
        AccessFs::Execute | AccessFs::ReadFile | AccessFs::ReadDir
    }

    fn other(error: impl std::fmt::Display) -> io::Error {
        io::Error::other(error.to_string())
    }

    /// Whether the running kernel enforces Landlock. A hard-requirement probe
    /// is needed: the default best-effort mode "succeeds" on kernels without
    /// Landlock by producing a ruleset that enforces nothing.
    pub(super) fn kernel_supports_landlock() -> bool {
        Ruleset::default()
            .set_compatibility(CompatLevel::HardRequirement)
            .handle_access(AccessFs::ReadFile)
            .and_then(Ruleset::create)
            .is_ok()
    }

    fn add_path(
        ruleset: RulesetCreated,
        path: &Path,
        access: landlock::BitFlags<AccessFs>,
        required: bool,
    ) -> io::Result<RulesetCreated> {
        let fd = match PathFd::new(path) {
            Ok(fd) => fd,
            Err(error) if !required => {
                log::debug!(
                    "[cwd_jail:landlock] skipping unavailable path {}: {error}",
                    path.display()
                );
                return Ok(ruleset);
            }
            Err(error) => {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("jail path {} cannot be opened: {error}", path.display()),
                ));
            }
        };
        ruleset
            .add_rule(PathBeneath::new(fd, access))
            .map_err(other)
    }

    fn build_ruleset(jail: &Jail) -> io::Result<RulesetCreated> {
        let (writes, reads) = (writes(), reads());
        let mut ruleset = Ruleset::default()
            .handle_access(writes | reads)
            .and_then(Ruleset::create)
            .map_err(other)?;
        // Baseline first: it is the least privileged and skipped when absent.
        for path in SYSTEM_READ_PATHS {
            ruleset = add_path(ruleset, Path::new(path), reads, false)?;
        }
        for path in DEVICE_PATHS {
            ruleset = add_path(ruleset, Path::new(path), writes | reads, false)?;
        }
        for path in &jail.read_only {
            ruleset = add_path(ruleset, path, reads, false)?;
        }
        // The root and read/write grants must exist: silently dropping them
        // would hand the child a jail it cannot write to, or worse a wrong one.
        ruleset = add_path(ruleset, &jail.root, writes | reads, true)?;
        for path in &jail.read_write {
            ruleset = add_path(ruleset, path, writes | reads, true)?;
        }
        Ok(ruleset)
    }

    pub(super) fn spawn(jail: &Jail, cmd: Command) -> io::Result<Child> {
        if !kernel_supports_landlock() {
            log::warn!(
                "[cwd_jail:landlock] kernel does not support Landlock; refusing to spawn \
                 unconfined (label={})",
                jail.label
            );
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Landlock is not supported by this kernel",
            ));
        }
        let ruleset = build_ruleset(jail)?;
        let label = jail.label.clone();
        let worker = std::thread::Builder::new()
            .name("tinybox-jail-spawn".into())
            .spawn(move || -> io::Result<Child> {
                let mut cmd = cmd;
                let status = ruleset.restrict_self().map_err(other)?;
                match status.ruleset {
                    RulesetStatus::NotEnforced => {
                        log::warn!(
                            "[cwd_jail:landlock] ruleset not enforced; refusing to spawn \
                             unconfined (label={label})"
                        );
                        return Err(io::Error::new(
                            io::ErrorKind::Unsupported,
                            "Landlock ruleset was not enforced",
                        ));
                    }
                    RulesetStatus::PartiallyEnforced => log::debug!(
                        "[cwd_jail:landlock] ruleset partially enforced (older kernel ABI) \
                         label={label}"
                    ),
                    RulesetStatus::FullyEnforced => {
                        log::trace!("[cwd_jail:landlock] ruleset fully enforced label={label}");
                    }
                }
                cmd.spawn()
            })?;
        worker
            .join()
            .map_err(|_| io::Error::other("Landlock spawn thread panicked"))?
    }
}

#[cfg(not(feature = "landlock"))]
mod imp {
    use std::io;
    use std::process::{Child, Command};

    use crate::jail::Jail;

    pub(super) fn kernel_supports_landlock() -> bool {
        false
    }

    pub(super) fn spawn(jail: &Jail, _cmd: Command) -> io::Result<Child> {
        log::warn!(
            "[cwd_jail:landlock] built without the `landlock` feature; refusing to spawn \
             unconfined (label={})",
            jail.label
        );
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "tinybox-jail was built without the `landlock` feature",
        ))
    }
}

#[cfg(test)]
#[path = "linux_tests.rs"]
mod tests;
