//! Whether a rootless systemd scope can really hold CPU, memory and pid limits.
//!
//! A trusted `systemd-run` on disk is not enough. The limits are applied by the
//! user's own systemd manager, which must be running and reachable, and which
//! can only set a limit for a cgroup controller it was delegated. Without that
//! a scope either fails to start or starts with the limit silently missing.
//! [`ScopeProbe`] reads both before any limit is claimed.

use tinybox_core::{Constraint, ConstraintSupport, Enforcement};

/// Which resource limits a rootless systemd scope can enforce here.
///
/// Each field is true only when the user manager is reachable and was
/// delegated that controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ScopeProbe {
    /// The `cpu` controller can be limited.
    pub cpu: bool,
    /// The `memory` controller can be limited.
    pub memory: bool,
    /// The `pids` controller can be limited.
    pub pids: bool,
}

impl ScopeProbe {
    /// Probe this machine: the user manager's socket under `$XDG_RUNTIME_DIR`
    /// (or the session bus socket), and the controllers listed in
    /// `/sys/fs/cgroup/user.slice/user-<uid>.slice/user@<uid>.service/cgroup.controllers`.
    #[must_use]
    pub fn detect() -> Self {
        let Some(uid) = current_uid() else {
            return Self::default();
        };
        let controllers = std::fs::read_to_string(format!(
            "/sys/fs/cgroup/user.slice/user-{uid}.slice/user@{uid}.service/cgroup.controllers"
        ))
        .ok();
        Self::from_parts(manager_socket_exists(), controllers.as_deref())
    }

    /// Build a probe from what was read: whether a manager socket exists, and
    /// the space-separated contents of the user manager's `cgroup.controllers`.
    #[must_use]
    pub fn from_parts(manager: bool, controllers: Option<&str>) -> Self {
        let has = |name: &str| {
            manager
                && controllers.is_some_and(|list| list.split_whitespace().any(|item| item == name))
        };
        Self {
            cpu: has("cpu"),
            memory: has("memory"),
            pids: has("pids"),
        }
    }

    /// `Cpu`, `Memory` and `Pids`: each `Enforced` only when its controller is
    /// delegated to a reachable manager, otherwise `Unsupported`.
    #[must_use]
    pub fn constraint_support(&self) -> ConstraintSupport {
        let level = |delegated: bool| {
            if delegated {
                Enforcement::Enforced
            } else {
                Enforcement::Unsupported
            }
        };
        ConstraintSupport::NONE
            .with(Constraint::Cpu, level(self.cpu))
            .with(Constraint::Memory, level(self.memory))
            .with(Constraint::Pids, level(self.pids))
    }
}

/// The real uid, read from the owner of `/proc/self`.
#[cfg(unix)]
fn current_uid() -> Option<u32> {
    use std::os::unix::fs::MetadataExt as _;
    std::fs::metadata("/proc/self").ok().map(|meta| meta.uid())
}

#[cfg(not(unix))]
fn current_uid() -> Option<u32> {
    None
}

/// `$XDG_RUNTIME_DIR/systemd/private`, or the session bus's `unix:path=`
/// socket, which `systemd-run --user` can reach the manager through.
#[cfg(unix)]
fn manager_socket_exists() -> bool {
    use std::os::unix::fs::FileTypeExt as _;
    let is_socket = |path: std::path::PathBuf| {
        path.is_absolute() && std::fs::metadata(path).is_ok_and(|meta| meta.file_type().is_socket())
    };
    let private = std::env::var_os("XDG_RUNTIME_DIR")
        .map(|dir| std::path::PathBuf::from(dir).join("systemd/private"));
    let bus = std::env::var("DBUS_SESSION_BUS_ADDRESS")
        .ok()
        .and_then(|address| {
            address
                .strip_prefix("unix:path=")
                .map(std::path::PathBuf::from)
        });
    private.into_iter().chain(bus).any(is_socket)
}

#[cfg(not(unix))]
fn manager_socket_exists() -> bool {
    false
}

#[cfg(test)]
#[path = "scope_tests.rs"]
mod tests;
