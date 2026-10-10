//! Cross-platform directory-jail facade.
//!
//! A [`Jail`] describes *what* the agent is allowed to see; a [`JailBackend`]
//! enforces it on a specific OS. Callers only interact with [`Jail`] and the
//! top-level [`crate::spawn`] function — they
//! never pick a backend by name.

use std::path::{Path, PathBuf};
use std::process::{Child, Command};

/// Declarative description of a directory jail.
///
/// One `root` (read/write), zero or more extra `read_write` paths, zero or
/// more `read_only` paths, and a network toggle.
/// Backends translate this into Landlock rules, a Seatbelt profile, or an
/// `AppContainer` ACL.
#[derive(Debug, Clone)]
pub struct Jail {
    /// Primary read/write root. The child cannot escape this directory for
    /// writes. Must be an existing, canonicalizable directory.
    pub root: PathBuf,
    /// Extra paths the child may read (e.g. `/usr/lib`, the runtime-node
    /// install). Writes are still denied.
    pub read_only: Vec<PathBuf>,
    /// Extra paths outside the root the child may read **and write**, with
    /// the same access the root gets. Meant for host-owned scratch the child
    /// must write to without it landing inside the root (e.g. a per-call
    /// output-capture directory). Grant the narrowest directory that works.
    pub read_write: Vec<PathBuf>,
    /// Allow outbound network. Most agent tools need this; some risky tools
    /// (untrusted code execution) should disable it.
    pub allow_net: bool,
    /// Allow the child to spawn further child processes. `AppContainer` and
    /// Seatbelt can deny this; Landlock cannot.
    pub allow_subprocess: bool,
    /// Free-form label used by audit logs and (on Windows) as the basis for
    /// the `AppContainer` profile name. Keep it short and ASCII.
    pub label: String,
}

impl Jail {
    /// Convenience: read/write jail rooted at `root` with networking enabled
    /// and no additional read-only mounts.
    pub fn new(root: impl AsRef<Path>, label: impl Into<String>) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
            read_only: Vec::new(),
            read_write: Vec::new(),
            allow_net: true,
            allow_subprocess: true,
            label: label.into(),
        }
    }

    /// Grants read (and execute) access to an extra path outside the root.
    #[must_use]
    pub fn add_read_only(mut self, path: impl AsRef<Path>) -> Self {
        self.read_only.push(path.as_ref().to_path_buf());
        self
    }

    /// Grants read and write access to an extra path outside the root.
    ///
    /// Backends grant it exactly what they grant the root: a Landlock rule on
    /// Linux, a `file-write*` subpath on macOS, an `AppContainer` ACL on
    /// Windows. The path should exist before spawning; backends that need an
    /// open handle (Landlock) fail the spawn when it does not.
    #[must_use]
    pub fn add_read_write(mut self, path: impl AsRef<Path>) -> Self {
        self.read_write.push(path.as_ref().to_path_buf());
        self
    }

    /// Requests network denial; strict preflight refuses unsupported backends.
    #[must_use]
    pub fn deny_net(mut self) -> Self {
        self.allow_net = false;
        self
    }

    /// Requests subprocess denial; strict preflight refuses unsupported backends.
    #[must_use]
    pub fn deny_subprocess(mut self) -> Self {
        self.allow_subprocess = false;
        self
    }

    /// Hard constraints implied by this jail's grants and denial flags.
    #[must_use]
    pub fn constraints(&self) -> Vec<tinybox_core::Constraint> {
        use tinybox_core::Constraint;
        let mut constraints = vec![Constraint::Filesystem];
        if !self.allow_net {
            constraints.push(Constraint::Network);
        }
        if !self.allow_subprocess {
            constraints.push(Constraint::Subprocess);
        }
        constraints
    }

    /// Canonicalize `root`, `read_only` and `read_write` so backends never see `..` or
    /// symlink trickery. Returns an error if `root` does not exist.
    ///
    /// # Errors
    ///
    /// Returns the filesystem error encountered while canonicalizing `root`.
    pub fn canonicalize(&mut self) -> std::io::Result<()> {
        self.root = self.root.canonicalize()?;
        for p in self.read_only.iter_mut().chain(self.read_write.iter_mut()) {
            if let Ok(c) = p.canonicalize() {
                *p = c;
            }
        }
        Ok(())
    }

    /// Best-effort canonicalize that swallows errors and logs them. Most
    /// callers should use the validating [`Jail::canonicalize`] path that
    /// [`crate::spawn`] runs automatically.
    pub fn canonicalize_or_log(&mut self) {
        if let Err(e) = self.canonicalize() {
            log::warn!(
                "[cwd_jail] failed to canonicalize jail root {}: {}",
                self.root.display(),
                e
            );
        }
    }
}

/// OS-specific enforcement of a [`Jail`].
///
/// We model spawning rather than `Command` mutation because Windows
/// `AppContainer` requires custom `CreateProcess` flags that `std`'s
/// `Command::spawn` does not expose.
pub trait JailBackend: Send + Sync {
    /// Stable identifier, used in logs / audit ("landlock", "seatbelt",
    /// "appcontainer", "noop").
    fn name(&self) -> &'static str;

    /// Whether the backend can actually enforce the jail in this process /
    /// on this kernel build. Auto-detection consults this before returning
    /// a backend.
    fn is_available(&self) -> bool;

    /// Declares implemented constraints; unknown backends claim nothing.
    fn constraint_support(&self) -> tinybox_core::ConstraintSupport {
        tinybox_core::ConstraintSupport::NONE
    }

    /// Process isolation provided by this backend, independent of path checks.
    fn isolation(&self) -> tinybox_core::IsolationLevel {
        tinybox_core::IsolationLevel::None
    }

    /// Whether the backend confines processes sufficiently for untrusted code.
    fn is_suitable_for_untrusted_code(&self) -> bool {
        self.isolation() >= tinybox_core::IsolationLevel::Kernel
            && self
                .constraint_support()
                .enforcement(tinybox_core::Constraint::Filesystem)
                == tinybox_core::Enforcement::Enforced
    }

    /// Inspect all hard constraints a directory jail requests.
    fn plan_check(&self, jail: &Jail) -> tinybox_core::PlanCheck {
        self.constraint_support().plan_check(&jail.constraints())
    }

    /// Refuse incomplete filesystem, network or subprocess confinement.
    ///
    /// # Errors
    /// Returns a typed constraint refusal before any child is spawned.
    fn require(&self, jail: &Jail) -> tinybox_core::Result<()> {
        self.constraint_support()
            .require(self.name(), &jail.constraints())
    }

    /// Spawn `cmd` under the jail described by `jail`. Backends own how the
    /// jail is materialized (Landlock ruleset, sandbox-exec wrapper,
    /// `AppContainer` profile + restricted token).
    ///
    /// # Errors
    ///
    /// Returns an error if the backend cannot apply the jail or spawn command.
    fn spawn(&self, jail: &Jail, cmd: Command) -> std::io::Result<Child>;
}

#[cfg(test)]
#[path = "jail_tests.rs"]
mod tests;
