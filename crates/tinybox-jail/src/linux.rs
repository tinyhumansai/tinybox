//! Linux backend: Landlock LSM (kernel 5.13+).
//!
//! Mirrors the host-side Landlock implementation
//! but wraps it behind the [`JailBackend`] trait so callers don't have to
//! plumb `SecurityConfig`. Landlock is applied via `pre_exec`, which runs
//! in the *child* process after `fork()` and before `exec()` — the parent
//! retains its broader privileges, the child gets the ruleset before any
//! user code runs. Same model used by Chromium's Linux sandbox.

#![cfg(target_os = "linux")]

use std::process::{Child, Command};

use super::jail::{Jail, JailBackend};

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
    pub fn new() -> Self {
        Self
    }
}

impl JailBackend for LandlockBackend {
    fn name(&self) -> &'static str {
        "landlock"
    }

    fn is_available(&self) -> bool {
        #[cfg(feature = "landlock")]
        {
            use landlock::{AccessFs, Ruleset, RulesetAttr};
            Ruleset::default()
                .handle_access(AccessFs::ReadFile)
                .and_then(|r| r.create())
                .is_ok()
        }
        #[cfg(not(feature = "landlock"))]
        {
            false
        }
    }

    fn spawn(&self, jail: &Jail, mut cmd: Command) -> std::io::Result<Child> {
        #[cfg(feature = "landlock")]
        {
            use landlock::{
                AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr,
            };
            use std::os::unix::process::CommandExt;

            let writes = AccessFs::WriteFile
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
                | AccessFs::Truncate;
            let reads = AccessFs::Execute | AccessFs::ReadFile | AccessFs::ReadDir;
            let mut ruleset = Ruleset::default()
                .handle_access(writes | reads)
                .and_then(|ruleset| ruleset.create())
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            let root_fd = PathFd::new(&jail.root)
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            ruleset = ruleset
                .add_rule(PathBeneath::new(root_fd, writes | reads))
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            for path in &jail.read_only {
                let fd =
                    PathFd::new(path).map_err(|error| std::io::Error::other(error.to_string()))?;
                ruleset = ruleset
                    .add_rule(PathBeneath::new(fd, reads))
                    .map_err(|error| std::io::Error::other(error.to_string()))?;
            }
            let mut ruleset = Some(ruleset);

            // SAFETY: the child callback only applies this prebuilt ruleset.
            unsafe {
                cmd.pre_exec(move || match ruleset.take() {
                    Some(ruleset) => match ruleset.restrict_self() {
                        Ok(_) => Ok(()),
                        Err(_) => Err(std::io::Error::from_raw_os_error(5)),
                    },
                    None => Err(std::io::Error::from_raw_os_error(22)),
                });
            }

            cmd.spawn()
        }
        #[cfg(not(feature = "landlock"))]
        {
            let _ = jail;
            cmd.spawn()
        }
    }
}
