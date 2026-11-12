//! CPU, memory and pid limits for a bubblewrap jail, through a rootless
//! systemd scope.
//!
//! The launcher runs under `systemd-run --user --scope` (see
//! `tinybox_linux::resource_scope_argv`), so the whole jail, `bwrap` and
//! everything inside it, lives in one transient cgroup holding the limits. Only
//! a limit whose controller the user manager was delegated is claimed or
//! applied ([`tinybox_linux::ScopeProbe`]). The scope's task count includes the
//! two or three host-side processes `bwrap` itself runs as.
//!
//! A jail that could reach the user manager could start a process outside its
//! scope. The baseline mounts expose neither `/run` (the manager's socket) nor
//! `/sys` (the cgroup tree), but a grant can, and a jail sharing the host
//! network shares its abstract sockets. A *hard* limit is therefore refused
//! for such a jail; a soft one is still applied, as a best effort.

use std::io;
use std::path::{Path, PathBuf};

use tinybox_core::{Constraint, ConstraintSupport, Enforcement};
use tinybox_linux::{ScopeLimits, ScopeProbe};

use crate::jail::Jail;

/// The constraints a scope can hold.
const LIMITS: [Constraint; 3] = [Constraint::Cpu, Constraint::Memory, Constraint::Pids];

/// Where the user manager's socket and the cgroup tree live.
const MANAGER_PATHS: [&str; 2] = ["/run", "/sys"];

/// A trusted `systemd-run` and what the user manager behind it was delegated.
#[derive(Debug, Clone)]
pub(super) struct ResourceScope {
    systemd_run: PathBuf,
    probe: ScopeProbe,
}

impl ResourceScope {
    /// The `systemd-run` at a fixed system location, probed once with the
    /// backend. `None` without one: then no limit is claimed.
    pub(super) fn detect() -> Option<Self> {
        let systemd_run = tinybox_linux::trusted_systemd_run_program().ok()?;
        Some(Self {
            systemd_run,
            probe: ScopeProbe::detect(),
        })
    }

    /// A scope with a given probe, for tests.
    #[cfg(test)]
    pub(super) fn with_probe(systemd_run: impl Into<PathBuf>, probe: ScopeProbe) -> Self {
        Self {
            systemd_run: systemd_run.into(),
            probe,
        }
    }

    fn enforcement(&self, constraint: Constraint) -> Enforcement {
        self.probe.constraint_support().enforcement(constraint)
    }
}

/// `support` with `Cpu`, `Memory` and `Pids` set to what `scope` can enforce
/// (`Unsupported` without one).
pub(super) fn with_limits(
    support: ConstraintSupport,
    scope: Option<&ResourceScope>,
) -> ConstraintSupport {
    LIMITS.into_iter().fold(support, |support, constraint| {
        let level = scope.map_or(Enforcement::Unsupported, |scope| {
            scope.enforcement(constraint)
        });
        support.with(constraint, level)
    })
}

/// The `systemd-run … --` prefix to run `jail`'s launcher under, or `None`
/// when the jail asks for no limit this scope can apply.
///
/// A soft limit the manager was not delegated is left out, and a soft request
/// whose scope command cannot be built runs unlimited. Hard limits the scope
/// cannot enforce never get here: preflight refuses them first.
///
/// # Errors
/// `Unsupported` when a hard limit is required of a jail that could leave its
/// scope (see the module docs), or when the scope command cannot be built for
/// one.
pub(super) fn prefix_for(
    jail: &Jail,
    scope: Option<&ResourceScope>,
    private_network: bool,
) -> io::Result<Option<Vec<String>>> {
    let (Some(resources), Some(scope)) = (jail.resources, scope) else {
        return Ok(None);
    };
    let hard = LIMITS
        .iter()
        .any(|limit| jail.hard_requirements.contains(limit));
    if hard && let Some(reason) = escape_route(jail, private_network) {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("bubblewrap cannot hold a hard resource limit for this jail: {reason}"),
        ));
    }
    let applied = |constraint, value: u64| {
        (scope.enforcement(constraint) == Enforcement::Enforced).then_some(value)
    };
    let limits = ScopeLimits {
        cpu_millis: applied(Constraint::Cpu, u64::from(resources.cpu_millis)),
        memory_bytes: applied(Constraint::Memory, resources.memory_bytes),
        pids_max: applied(Constraint::Pids, u64::from(resources.pids_max)),
    };
    if limits == ScopeLimits::default() {
        return Ok(None);
    }
    match tinybox_linux::resource_scope_argv(&scope.systemd_run, "bwrap", limits) {
        Ok(argv) => Ok(Some(argv)),
        Err(error) if !hard => {
            log::debug!("[cwd_jail:bwrap] soft limits not applied: {error}");
            Ok(None)
        }
        Err(error) => Err(io::Error::new(io::ErrorKind::Unsupported, error)),
    }
}

/// How `jail` could reach the user manager, if it could.
fn escape_route(jail: &Jail, private_network: bool) -> Option<&'static str> {
    if jail.allow_net && !private_network {
        return Some("it shares the host network, whose abstract sockets reach the user manager");
    }
    let exposes = |path: &PathBuf| {
        MANAGER_PATHS
            .iter()
            .any(|managed| path.starts_with(managed) || Path::new(managed).starts_with(path))
    };
    std::iter::once(&jail.root)
        .chain(&jail.read_only)
        .chain(&jail.read_write)
        .any(exposes)
        .then_some("a grant exposes /run or /sys, where the user manager and the cgroup tree live")
}

#[cfg(test)]
#[path = "scope_tests.rs"]
mod tests;
