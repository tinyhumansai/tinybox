//! Discoverability for the namespace backend's prerequisites.
//!
//! [`NamespaceSandbox`](crate::NamespaceSandbox) needs `bwrap` on `PATH` and
//! permission for an unprivileged process to create a user namespace. Either
//! can be missing without any hint at the point of use: Ubuntu 24.04 ships
//! `kernel.apparmor_restrict_unprivileged_userns=1`, which makes `bwrap` fail
//! with a bare "Operation not permitted". [`NamespaceProbe`] looks before the
//! first command runs and turns that into an actionable message, so a caller
//! can choose another backend or fail closed instead of guessing.

use std::path::{Path, PathBuf};

mod scope;

pub use scope::ScopeProbe;

/// Whether an unprivileged process may create a user namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsernsStatus {
    /// No sysctl known to block user namespaces is set.
    Available,
    /// `user.max_user_namespaces` is zero, or Debian's
    /// `kernel.unprivileged_userns_clone` is zero.
    DisabledBySysctl,
    /// `kernel.apparmor_restrict_unprivileged_userns` is `1` (Ubuntu 24.04),
    /// so only binaries with an `AppArmor` profile granting `userns` may create
    /// one.
    RestrictedByAppArmor,
}

impl UsernsStatus {
    /// Derive the status from raw sysctl file contents (`None` when the file
    /// does not exist). Disabling wins over `AppArmor` restriction because it is
    /// the harder block.
    #[must_use]
    pub fn from_sysctls(
        max_user_namespaces: Option<&str>,
        unprivileged_userns_clone: Option<&str>,
        apparmor_restrict: Option<&str>,
    ) -> Self {
        if max_user_namespaces.is_some_and(|value| value.trim() == "0")
            || unprivileged_userns_clone.is_some_and(|value| value.trim() == "0")
        {
            Self::DisabledBySysctl
        } else if apparmor_restrict.is_some_and(|value| value.trim() == "1") {
            Self::RestrictedByAppArmor
        } else {
            Self::Available
        }
    }
}

/// What the namespace backend found on this machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceProbe {
    /// Where `bwrap` was found, if anywhere.
    pub bwrap: Option<PathBuf>,
    /// Whether user namespaces can be created without privilege.
    pub userns: UsernsStatus,
}

impl NamespaceProbe {
    /// Probe this machine: `PATH` for `bwrap`, and the user-namespace sysctls.
    #[must_use]
    pub fn detect() -> Self {
        let path = std::env::var_os("PATH").unwrap_or_default();
        let read = |name: &str| std::fs::read_to_string(Path::new("/proc/sys").join(name)).ok();
        Self {
            bwrap: find_on_path("bwrap", &path),
            userns: UsernsStatus::from_sysctls(
                read("user/max_user_namespaces").as_deref(),
                read("kernel/unprivileged_userns_clone").as_deref(),
                read("kernel/apparmor_restrict_unprivileged_userns").as_deref(),
            ),
        }
    }

    /// Whether the backend can be expected to start a box.
    #[must_use]
    pub fn is_usable(&self) -> bool {
        self.problem().is_none()
    }

    /// The first thing wrong, phrased as what to do about it.
    #[must_use]
    pub fn problem(&self) -> Option<String> {
        if self.bwrap.is_none() {
            return Some(
                "bwrap is not on PATH; install bubblewrap (for example `apt install bubblewrap`)"
                    .to_owned(),
            );
        }
        match self.userns {
            UsernsStatus::Available => None,
            UsernsStatus::DisabledBySysctl => Some(
                "unprivileged user namespaces are disabled; set user.max_user_namespaces above 0 \
                 (and kernel.unprivileged_userns_clone=1 on Debian), or use another backend"
                    .to_owned(),
            ),
            UsernsStatus::RestrictedByAppArmor => Some(
                "AppArmor restricts unprivileged user namespaces \
                 (kernel.apparmor_restrict_unprivileged_userns=1, the Ubuntu 24.04 default); \
                 install an AppArmor profile that grants `userns` to bwrap, or use another backend"
                    .to_owned(),
            ),
        }
    }
}

/// The first executable regular file named `program` in the `PATH`-style list.
fn find_on_path(program: &str, path: &std::ffi::OsStr) -> Option<PathBuf> {
    std::env::split_paths(path)
        .map(|dir| dir.join(program))
        .find(|candidate| is_executable(candidate))
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::metadata(path)
        .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
