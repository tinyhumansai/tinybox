//! Cross-platform directory-jail facade.
//!
//! A [`Jail`] describes *what* the agent is allowed to see; a [`JailBackend`]
//! enforces it on a specific OS. Callers only interact with [`Jail`] and the
//! top-level [`crate::spawn`] function — they
//! never pick a backend by name.

use std::fs::File;
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
    /// Paths the child may neither read nor write. A backend that
    /// [`carves_denials`](JailBackend::carves_denials) subtracts them from
    /// grants; allow-list backends deny paths outside grants by default. The
    /// native module rejects overlaps that an allow-list backend cannot enforce.
    /// Missing paths are retained so backend rules can cover later creation.
    pub deny_read: Vec<PathBuf>,
    /// Optional resource values to apply where the backend supports them.
    ///
    /// These values are defaults, not hard requirements. Use
    /// [`hard_requirements`](Self::hard_requirements) to require enforcement.
    pub resources: Option<tinybox_core::Resources>,
    /// Constraints the backend must enforce fully before spawning.
    pub hard_requirements: Vec<tinybox_core::Constraint>,
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
            deny_read: Vec::new(),
            resources: None,
            hard_requirements: Vec::new(),
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

    /// Require the backend to fully enforce each listed constraint.
    #[must_use]
    pub fn with_hard_requirements(
        mut self,
        requirements: impl IntoIterator<Item = tinybox_core::Constraint>,
    ) -> Self {
        self.hard_requirements = requirements.into_iter().collect();
        self.deny_required()
    }

    /// Copy resource defaults and hard constraints from a box specification.
    /// Filesystem roots and grants remain explicit Jail data; a hard network
    /// or subprocess requirement denies that access.
    #[must_use]
    pub fn with_box_spec(mut self, spec: &tinybox_core::BoxSpec) -> Self {
        self.resources = Some(spec.resources);
        self.hard_requirements.clone_from(&spec.hard_requirements);
        self.deny_required()
    }

    /// A hard `Network` or `Subprocess` requirement is a denial, so the flags
    /// backends launch from agree with what preflight checked.
    fn deny_required(mut self) -> Self {
        use tinybox_core::Constraint;
        self.allow_net &= !self.hard_requirements.contains(&Constraint::Network);
        self.allow_subprocess &= !self.hard_requirements.contains(&Constraint::Subprocess);
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
        for constraint in &self.hard_requirements {
            if !constraints.contains(constraint) {
                constraints.push(*constraint);
            }
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
        self.reject_symlinked_grants()?;
        self.root = self.root.canonicalize()?;
        for p in self
            .read_only
            .iter_mut()
            .chain(self.read_write.iter_mut())
            .chain(self.deny_read.iter_mut())
        {
            if let Ok(c) = p.canonicalize() {
                *p = c;
            }
        }
        self.deny_read = self
            .deny_read
            .iter()
            .map(|path| crate::registry::canonicalize_missing(path))
            .collect::<std::io::Result<Vec<_>>>()?;
        self.deny_read.sort();
        self.deny_read.dedup();
        Ok(())
    }

    /// Runs [`reject_symlinked_grants`] over this jail's own paths.
    fn reject_symlinked_grants(&self) -> std::io::Result<()> {
        let writable: Vec<&Path> = std::iter::once(&self.root)
            .chain(&self.read_write)
            .map(PathBuf::as_path)
            .collect();
        let grants: Vec<&Path> = self
            .read_only
            .iter()
            .chain(&self.read_write)
            .map(PathBuf::as_path)
            .collect();
        reject_symlinked_grants(&writable, &grants)
    }

    /// Refuse denials that a non-carving backend cannot preserve against its
    /// explicit and implicit grants after path canonicalization.
    pub(crate) fn validate_denials(
        &self,
        carves_denials: bool,
        implicit_grants: &[PathBuf],
    ) -> std::io::Result<()> {
        if carves_denials || self.deny_read.is_empty() {
            return Ok(());
        }
        let implicit_grants = implicit_grants
            .iter()
            .map(|path| crate::registry::canonicalize_missing(path))
            .collect::<std::io::Result<Vec<_>>>()?;
        for denied in &self.deny_read {
            if std::iter::once(&self.root)
                .chain(&self.read_only)
                .chain(&self.read_write)
                .chain(&implicit_grants)
                .any(|granted| denied.starts_with(granted) || granted.starts_with(denied))
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "denied path overlaps an allow-list or implicit grant",
                ));
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

/// Refuses a read-only or read-write grant that sits inside a writable root or
/// grant and reaches its target through a symlink below that ancestor.
///
/// The jailed program can plant such a link (`vendor -> /secret`) in a writable
/// directory; canonicalizing the grant would silently turn a later session's
/// grant into a mount of the link's target. **Call this on the raw,
/// un-canonicalized paths**: once a grant is canonicalized the link is gone and
/// there is nothing left to detect. The ancestor is matched however the grant
/// spells it (the path itself, its canonical form, or any alias that resolves
/// to it).
///
/// # Errors
/// `InvalidInput` naming the symlink.
pub fn reject_symlinked_grants(writable: &[&Path], grants: &[&Path]) -> std::io::Result<()> {
    for ancestor in writable {
        let canonical = ancestor.canonicalize().ok();
        for grant in grants {
            if grant == ancestor {
                continue;
            }
            // The shortest prefix of the grant that names the ancestor.
            let mut prefixes: Vec<&Path> = grant.ancestors().collect();
            prefixes.reverse();
            let anchor = prefixes.into_iter().find(|prefix| {
                *prefix == *ancestor
                    || canonical
                        .as_ref()
                        .is_some_and(|c| prefix.canonicalize().is_ok_and(|p| p == *c))
            });
            if let Some(anchor) = anchor {
                reject_symlink_below(anchor, grant)?;
            }
        }
    }
    Ok(())
}

/// Errors when `path` lies inside `ancestor` (lexically) and any component
/// below `ancestor` is a symlink. A path equal to `ancestor` passes.
///
/// # Errors
/// `InvalidInput` naming the symlink.
pub(crate) fn reject_symlink_below(ancestor: &Path, path: &Path) -> std::io::Result<()> {
    let Ok(rest) = path.strip_prefix(ancestor) else {
        return Ok(());
    };
    let mut current = ancestor.to_path_buf();
    for component in rest.components() {
        current.push(component);
        match std::fs::symlink_metadata(&current) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "grant {} reaches {} through a symlink inside writable {}",
                        path.display(),
                        current.display(),
                        ancestor.display()
                    ),
                ));
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }
    Ok(())
}

/// Refuses `deny` when it sits two or more levels inside `writable`: the child
/// could rename the directory in between and read the denied path under its
/// new name, which a path-based mask or profile rule no longer matches. A
/// direct child of `writable` (or a path outside it) passes.
#[must_use]
pub fn nested_denial(deny: &Path, writable: &Path) -> Option<std::io::Error> {
    if !deny.starts_with(writable) || deny.parent() == Some(writable) {
        return None;
    }
    Some(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!(
            "deny_read {} is nested inside writable grant {}; the child could rename \
             a parent directory and bypass the mask (deny a direct child of the grant, \
             or make the grant read-only)",
            deny.display(),
            writable.display()
        ),
    ))
}

/// OS-specific enforcement of a [`Jail`].
///
/// We model spawning rather than `Command` mutation because Windows
/// `AppContainer` requires custom `CreateProcess` flags that `std`'s
/// `Command::spawn` does not expose.
pub trait JailBackend: Send + Sync {
    /// Paths the backend implicitly grants in addition to explicit jail roots.
    ///
    /// Callers enforcing hard denials use these paths to detect overlaps that
    /// the backend's allow rules would otherwise override. Backends should
    /// report every recursively granted baseline path; the default means the
    /// backend has no implicit filesystem grants.
    fn implicit_grants(&self) -> Vec<PathBuf> {
        Vec::new()
    }

    /// Whether [`Jail::deny_read`] is enforced even inside the root or a grant.
    /// Allow-list backends (Landlock, `AppContainer`) cannot subtract from a
    /// grant, so they keep the default `false`.
    fn carves_denials(&self) -> bool {
        false
    }

    /// Refuses a [`Jail::deny_read`] entry this backend's carve cannot hold.
    /// Callers run it before admitting a jail; the default refuses nothing.
    ///
    /// # Errors
    /// `InvalidInput` naming the denial.
    fn validate_carved_denials(&self, _jail: &Jail) -> std::io::Result<()> {
        Ok(())
    }

    /// Stable identifier, used in logs / audit ("landlock", "seatbelt",
    /// "appcontainer", "noop").
    fn name(&self) -> &'static str;

    /// Whether the backend can actually enforce the jail in this process /
    /// on this kernel build. Auto-detection consults this before returning
    /// a backend.
    fn is_available(&self) -> bool;

    /// Whether the backend can spawn through [`OwnedChild`]. Backends that
    /// cannot expose a `std::process::Child` may override this independently.
    fn is_owned_available(&self) -> bool {
        self.is_available()
    }

    /// Declares implemented constraints; unknown backends claim nothing.
    fn constraint_support(&self) -> tinybox_core::ConstraintSupport {
        tinybox_core::ConstraintSupport::NONE
    }

    /// Process isolation this backend guarantees for **any** jail it accepts,
    /// independent of path checks. A backend whose isolation depends on the
    /// configuration reports its weakest case here and the actual level from
    /// [`isolation_for`](Self::isolation_for).
    fn isolation(&self) -> tinybox_core::IsolationLevel {
        tinybox_core::IsolationLevel::None
    }

    /// Whether the backend confines processes sufficiently for untrusted code
    /// under *every* configuration it accepts. Prefer
    /// [`is_suitable_for_untrusted_jail`](Self::is_suitable_for_untrusted_jail)
    /// when you hold the jail: it can be true where this is false.
    fn is_suitable_for_untrusted_code(&self) -> bool {
        self.isolation() >= tinybox_core::IsolationLevel::Kernel
            && self
                .constraint_support()
                .enforcement(tinybox_core::Constraint::Filesystem)
                == tinybox_core::Enforcement::Enforced
    }

    /// Process isolation this backend provides for one specific `jail`.
    ///
    /// Defaults to [`isolation`](Self::isolation). A backend whose isolation
    /// depends on the configuration (a shared network namespace when
    /// `allow_net` is set) lowers it here. Hosts deciding whether to run
    /// untrusted code should use
    /// [`is_suitable_for_untrusted_jail`](Self::is_suitable_for_untrusted_jail).
    fn isolation_for(&self, _jail: &Jail) -> tinybox_core::IsolationLevel {
        self.isolation()
    }

    /// Per-configuration form of
    /// [`is_suitable_for_untrusted_code`](Self::is_suitable_for_untrusted_code).
    fn is_suitable_for_untrusted_jail(&self, jail: &Jail) -> bool {
        self.isolation_for(jail) >= tinybox_core::IsolationLevel::Kernel
            && self
                .constraint_support()
                .enforcement(tinybox_core::Constraint::Filesystem)
                == tinybox_core::Enforcement::Enforced
    }

    /// Inspect all hard constraints a directory jail requests.
    fn plan_check(&self, jail: &Jail) -> tinybox_core::PlanCheck {
        self.constraint_support().plan_check(&jail.constraints())
    }

    /// Inspect only the hard requirements explicitly listed on a box spec.
    fn plan_check_spec(&self, spec: &tinybox_core::BoxSpec) -> tinybox_core::PlanCheck {
        self.constraint_support()
            .plan_check(&spec.hard_requirements)
    }

    /// Refuse a box spec when any explicit hard requirement is unsupported.
    ///
    /// # Errors
    /// Returns a typed refusal naming the first unsupported hard constraint.
    fn require_spec(&self, spec: &tinybox_core::BoxSpec) -> tinybox_core::Result<()> {
        self.constraint_support()
            .require(self.name(), &spec.hard_requirements)
    }

    /// Refuse incomplete filesystem, network or subprocess confinement.
    ///
    /// # Errors
    /// Returns a typed constraint refusal before any child is spawned.
    fn require(&self, jail: &Jail) -> tinybox_core::Result<()> {
        self.constraint_support()
            .require(self.name(), &jail.constraints())
    }

    /// Validate resource values and preflight every explicit hard requirement.
    ///
    /// # Errors
    /// Returns a typed refusal if any listed hard constraint is not fully enforced.
    fn require_resources(&self, jail: &Jail) -> tinybox_core::Result<()> {
        if let Some(resources) = jail.resources {
            resources.validate()?;
        }
        self.constraint_support()
            .require(self.name(), &jail.hard_requirements)?;
        Ok(())
    }

    /// Spawn `cmd` under the jail described by `jail`. Callers must run
    /// [`JailBackend::require_resources`] before calling this method when
    /// `jail.resources` is present. Backends own how the
    /// jail is materialized (Landlock ruleset, sandbox-exec wrapper,
    /// `AppContainer` profile + restricted token).
    ///
    /// # Errors
    ///
    /// Returns an error if the backend cannot apply the jail or spawn command.
    fn spawn(&self, jail: &Jail, cmd: Command) -> std::io::Result<Child>;

    /// Spawn with module-owned stdin, stdout, and stderr pipes.
    /// Wrapping providers must apply these pipes to their actual launcher.
    /// On Unix, providers must also honor `Command` process-group settings.
    /// Callers must run [`JailBackend::require_resources`] first when
    /// `jail.resources` is present.
    /// # Errors
    /// Returns the provider's confinement or native startup error.
    fn spawn_captured(&self, jail: &Jail, mut cmd: Command) -> std::io::Result<Child> {
        cmd.stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        self.spawn(jail, cmd)
    }

    /// Spawn captured work through the owned-child boundary.
    ///
    /// Backends that need a custom process owner may override this method to
    /// provide pipe files and process supervision without exposing a
    /// `std::process::Child`. The default adapter owns only the direct child;
    /// override it when the backend must also own and stop descendants.
    /// Implementations of [`OwnedProcess::terminate`] must return promptly;
    /// callers bound asynchronous waiting, but cannot preempt a blocking
    /// synchronous termination operation. Existing backends use the default
    /// adapter. The default adapter requests a new local process group before
    /// spawning and records the returned standard child's ID as that group;
    /// custom owned adapters must set group metadata explicitly only when
    /// they own a verified local process group.
    /// # Errors
    /// Returns the provider's confinement or native startup error.
    fn spawn_owned_captured(&self, jail: &Jail, cmd: Command) -> std::io::Result<OwnedChild> {
        #[cfg(unix)]
        let cmd = {
            use std::os::unix::process::CommandExt;
            let mut cmd = cmd;
            cmd.process_group(0);
            cmd
        };
        let child = self.spawn_captured(jail, cmd)?;
        #[cfg(unix)]
        {
            let group = child.id();
            OwnedChild::from_std(child).map(|child| child.with_local_process_group_id(group))
        }
        #[cfg(not(unix))]
        {
            OwnedChild::from_std(child)
        }
    }

    /// Spawn captured work with exactly the environment approved by the host.
    /// The default clears `cmd`'s environment and applies `env` before
    /// delegating; native launchers must build the child environment from
    /// `env` instead of inheriting the parent's.
    /// # Errors
    /// Returns a confinement or native startup error.
    fn spawn_owned_captured_with_env(
        &self,
        jail: &Jail,
        mut cmd: Command,
        env: &std::collections::BTreeMap<String, String>,
    ) -> std::io::Result<OwnedChild> {
        cmd.env_clear().envs(env);
        self.spawn_owned_captured(jail, cmd)
    }
}

/// Exit information independent of a platform-specific child handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChildStatus {
    code: Option<i32>,
}

impl ChildStatus {
    /// Construct status from the native process exit code. Signal termination
    /// is represented by `None` on platforms that expose it that way.
    #[must_use]
    pub const fn from_code(code: Option<i32>) -> Self {
        Self { code }
    }

    /// Exit code when the process has one (signal termination has none).
    #[must_use]
    pub const fn code(self) -> Option<i32> {
        self.code
    }

    /// Whether the process returned exit code zero.
    #[must_use]
    pub const fn success(self) -> bool {
        matches!(self.code, Some(0))
    }
}

/// Process operations retained independently from its captured standard pipes.
///
/// Implementations must not report completion until the owned process has
/// exited. `terminate` must return promptly and stop every process the
/// backend owns for this run. A backend that owns only the direct child must
/// document that boundary; callers may separately supervise a process group.
pub trait OwnedProcess: Send {
    /// Native identifier, when one is available.
    fn id(&self) -> Option<u32>;
    /// Nonblocking completion check.
    /// # Errors
    /// Returns an operating-system error while inspecting the process.
    fn try_wait(&mut self) -> std::io::Result<Option<ChildStatus>>;
    /// Stop the processes this backend owns, returning promptly.
    ///
    /// The standard-child adapter owns and stops only the direct child. A
    /// backend may stop descendants when it has an explicit ownership
    /// mechanism, such as a process group or job object. This synchronous
    /// method must not perform unbounded blocking work because async callers
    /// cannot preempt it with a timeout.
    /// # Errors
    /// Returns an operating-system error while terminating the process.
    fn terminate(&mut self) -> std::io::Result<()>;
}

/// A captured process whose process owner and standard pipes can be supplied
/// independently by a jail backend.
pub struct OwnedChild {
    process: Box<dyn OwnedProcess>,
    local_process_group_id: Option<u32>,
    stdin: Option<File>,
    stdout: Option<File>,
    stderr: Option<File>,
}

impl std::fmt::Debug for OwnedChild {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnedChild")
            .field("id", &self.id())
            .field("has_stdin", &self.stdin.is_some())
            .field("has_stdout", &self.stdout.is_some())
            .field("has_stderr", &self.stderr.is_some())
            .finish_non_exhaustive()
    }
}

impl OwnedChild {
    /// Construct an owned child from a process adapter and its captured pipes.
    #[must_use]
    pub fn new(
        process: impl OwnedProcess + 'static,
        stdin: Option<File>,
        stdout: Option<File>,
        stderr: Option<File>,
    ) -> Self {
        Self {
            process: Box::new(process),
            local_process_group_id: None,
            stdin,
            stdout,
            stderr,
        }
    }

    /// Adapt a standard child and its configured pipes to the owned interface.
    /// # Errors
    /// Returns an error on platforms where standard child pipes cannot be
    /// converted into owned files.
    pub fn from_std(child: Child) -> std::io::Result<Self> {
        let mut child = StdOwnedProcess(child);
        let stdin = child.0.stdin.take().map(child_stdin_file).transpose()?;
        let stdout = child.0.stdout.take().map(child_stdout_file).transpose()?;
        let stderr = child.0.stderr.take().map(child_stderr_file).transpose()?;
        Ok(Self::new(child, stdin, stdout, stderr))
    }

    /// Native child identifier, when available.
    #[must_use]
    pub fn id(&self) -> Option<u32> {
        self.process.id()
    }

    /// Attach the verified ID of a local process group this backend owns.
    ///
    /// This is separate from [`OwnedProcess::id`], which may be a brokered or
    /// otherwise nonlocal native ID. Call this only when the backend can prove
    /// that the value names a local process group safe for the host to signal.
    #[must_use]
    pub fn with_local_process_group_id(mut self, id: u32) -> Self {
        self.local_process_group_id = Some(id);
        self
    }

    /// Verified local process-group ID owned by this backend, if any.
    #[must_use]
    pub const fn local_process_group_id(&self) -> Option<u32> {
        self.local_process_group_id
    }

    /// Nonblocking process completion check.
    /// # Errors
    /// Returns an operating-system error while inspecting the process.
    pub fn try_wait(&mut self) -> std::io::Result<Option<ChildStatus>> {
        self.process.try_wait()
    }

    /// Stop the processes owned by this backend, returning promptly.
    ///
    /// The standard-child adapter stops only the direct child; backends with
    /// an explicit process-tree ownership mechanism may stop descendants.
    /// # Errors
    /// Returns an operating-system error while terminating the process.
    pub fn terminate(&mut self) -> std::io::Result<()> {
        self.process.terminate()
    }

    /// Take the captured stdin pipe.
    pub fn take_stdin(&mut self) -> Option<File> {
        self.stdin.take()
    }

    /// Take the captured stdout pipe.
    pub fn take_stdout(&mut self) -> Option<File> {
        self.stdout.take()
    }

    /// Take the captured stderr pipe.
    pub fn take_stderr(&mut self) -> Option<File> {
        self.stderr.take()
    }

    #[cfg(all(test, unix))]
    pub(crate) fn stdout_mut(&mut self) -> Option<&mut File> {
        self.stdout.as_mut()
    }

    #[cfg(all(test, unix))]
    pub(crate) fn stderr_mut(&mut self) -> Option<&mut File> {
        self.stderr.as_mut()
    }
}

struct StdOwnedProcess(Child);

impl OwnedProcess for StdOwnedProcess {
    fn id(&self) -> Option<u32> {
        Some(self.0.id())
    }

    fn try_wait(&mut self) -> std::io::Result<Option<ChildStatus>> {
        self.0.try_wait().map(|status| {
            status.map(|status| ChildStatus {
                code: status.code(),
            })
        })
    }

    fn terminate(&mut self) -> std::io::Result<()> {
        self.0.kill()
    }
}

#[cfg(unix)]
#[allow(clippy::unnecessary_wraps)] // Other targets return Unsupported for this conversion.
fn child_stdin_file(pipe: std::process::ChildStdin) -> std::io::Result<File> {
    use std::os::fd::OwnedFd;
    Ok(File::from(OwnedFd::from(pipe)))
}

#[cfg(unix)]
#[allow(clippy::unnecessary_wraps)] // Other targets return Unsupported for this conversion.
fn child_stdout_file(pipe: std::process::ChildStdout) -> std::io::Result<File> {
    use std::os::fd::OwnedFd;
    Ok(File::from(OwnedFd::from(pipe)))
}

#[cfg(unix)]
#[allow(clippy::unnecessary_wraps)] // Other targets return Unsupported for this conversion.
fn child_stderr_file(pipe: std::process::ChildStderr) -> std::io::Result<File> {
    use std::os::fd::OwnedFd;
    Ok(File::from(OwnedFd::from(pipe)))
}

#[cfg(windows)]
#[allow(clippy::unnecessary_wraps)] // Other targets return Unsupported for this conversion.
fn child_stdin_file(pipe: std::process::ChildStdin) -> std::io::Result<File> {
    use std::os::windows::io::OwnedHandle;
    Ok(File::from(OwnedHandle::from(pipe)))
}

#[cfg(windows)]
#[allow(clippy::unnecessary_wraps)] // Other targets return Unsupported for this conversion.
fn child_stdout_file(pipe: std::process::ChildStdout) -> std::io::Result<File> {
    use std::os::windows::io::OwnedHandle;
    Ok(File::from(OwnedHandle::from(pipe)))
}

#[cfg(windows)]
#[allow(clippy::unnecessary_wraps)] // Other targets return Unsupported for this conversion.
fn child_stderr_file(pipe: std::process::ChildStderr) -> std::io::Result<File> {
    use std::os::windows::io::OwnedHandle;
    Ok(File::from(OwnedHandle::from(pipe)))
}

#[cfg(not(any(unix, windows)))]
fn unsupported_pipe<T>(_pipe: T) -> std::io::Result<File> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "captured child pipes are unsupported on this platform",
    ))
}

#[cfg(not(any(unix, windows)))]
fn child_stdin_file(pipe: std::process::ChildStdin) -> std::io::Result<File> {
    unsupported_pipe(pipe)
}

#[cfg(not(any(unix, windows)))]
fn child_stdout_file(pipe: std::process::ChildStdout) -> std::io::Result<File> {
    unsupported_pipe(pipe)
}

#[cfg(not(any(unix, windows)))]
fn child_stderr_file(pipe: std::process::ChildStderr) -> std::io::Result<File> {
    unsupported_pipe(pipe)
}

#[cfg(test)]
#[path = "jail_tests.rs"]
mod tests;
