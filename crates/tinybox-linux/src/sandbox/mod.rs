//! A rootless sandbox built on Linux namespaces.

use std::sync::Arc;

use async_trait::async_trait;
use tinybox_core::{
    BoxId, BoxInfo, BoxSpec, BoxState, Capability, Clock, Error, ExecOutput, ExecRequest, Host,
    IsolationLevel, Result, Sandbox, SandboxCapabilities, SnapshotId, SnapshotSupport, Store,
    SystemClock,
};

mod args;

pub use args::WORKSPACE_MOUNT;

/// The name this sandbox registers under.
pub const NAME: &str = "namespace";

/// A sandbox that runs each command in its own set of Linux namespaces.
///
/// Unprivileged throughout: no daemon, no setuid helper of tinybox's own, and
/// no root. The workload gets a private process table, a private mount tree, a
/// private network namespace, and a read-only view of the system's programs.
///
/// # It drives `bwrap`
///
/// Namespace setup goes through [bubblewrap] rather than raw `clone` and
/// `pivot_root`, for a reason that is practical rather than aesthetic: modern
/// Ubuntu sets `kernel.apparmor_restrict_unprivileged_userns=1`, which stops an
/// ordinary binary from creating a user namespace at all. `bwrap` ships an
/// `AppArmor` profile that permits it, so a hand-written backend would fail on
/// the most common Linux distribution while this one works. ADR 0005 records
/// that in full.
///
/// # What a box actually is here
///
/// A record and a bound directory — not a running container. Each command is a
/// fresh sandbox over the same workspace, so **writes outside the workspace do
/// not survive between commands**. That is why this backend declares no
/// snapshot support: there is no persistent filesystem to capture.
///
/// [bubblewrap]: https://github.com/containers/bubblewrap
#[derive(Debug, Clone)]
pub struct NamespaceSandbox {
    host: Arc<dyn Host>,
    store: Arc<dyn Store>,
    clock: Arc<dyn Clock>,
    limits: bool,
}

impl NamespaceSandbox {
    /// Run sandboxed commands on `host`, recording boxes in `store`.
    ///
    /// Resource limits are **not** declared: they need a systemd user session
    /// to delegate a cgroup, which not every machine has. Ask for them with
    /// [`NamespaceSandbox::with_cgroup_limits`].
    #[must_use]
    pub fn new(host: Arc<dyn Host>, store: Arc<dyn Store>) -> Self {
        Self {
            host,
            store,
            clock: Arc::new(SystemClock::new()),
            limits: false,
        }
    }

    /// Apply resource limits through a transient systemd user scope.
    ///
    /// Opt-in because it depends on the machine: rootless cgroup v2 limits are
    /// only available through the user's own systemd session. When this is on,
    /// a machine that cannot provide the scope fails the command rather than
    /// running it unlimited — declaring a limit and not applying it is the one
    /// outcome worth avoiding.
    #[must_use]
    pub fn with_cgroup_limits(mut self) -> Self {
        self.limits = true;
        self
    }

    /// Read creation times from `clock` rather than the operating system.
    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// What this sandbox declares, given whether limits are enabled.
    ///
    /// No snapshots, because each command is a fresh sandbox and there is no
    /// persistent filesystem to capture. No forking, for the same reason. No
    /// port forwarding: the network namespace is empty by design and there is
    /// no daemon to publish through.
    #[must_use]
    pub const fn declared_capabilities(limits: bool) -> SandboxCapabilities {
        let declared = SandboxCapabilities::new(IsolationLevel::Kernel, SnapshotSupport::None);
        if limits {
            declared.with_resource_limits()
        } else {
            declared
        }
    }
}

#[async_trait]
impl Sandbox for NamespaceSandbox {
    fn name(&self) -> &'static str {
        NAME
    }

    fn capabilities(&self) -> SandboxCapabilities {
        Self::declared_capabilities(self.limits)
    }

    async fn create(&self, spec: &BoxSpec) -> Result<BoxInfo> {
        spec.validate()?;
        // Nothing is started here: a box is a record plus a directory, and the
        // sandbox itself exists only for the length of a command. Checking the
        // source now means an unusable spec fails at `create` rather than
        // surprising the caller at the first `exec`.
        args::workspace_dir(spec)?;

        tinybox_core::insert_new(self.store.as_ref(), BoxState::Ready, spec, self.clock.now())
    }

    async fn exec(&self, id: &BoxId, request: &ExecRequest) -> Result<ExecOutput> {
        let info = self.store.get(id)?;
        if !info.state.accepts_commands() {
            return Err(Error::InvalidState {
                id: id.as_str().to_owned(),
                actual: info.state,
                expected: BoxState::Ready,
            });
        }

        let argv = args::exec(&info.spec, request, self.limits)?;
        // A command that runs and fails is a result, so the raw output is
        // returned rather than being turned into a backend error.
        self.host.run(&ExecRequest::new(argv)).await
    }

    async fn snapshot(&self, _id: &BoxId) -> Result<SnapshotId> {
        Err(Error::Unsupported {
            sandbox: NAME.to_owned(),
            capability: Capability::FilesystemSnapshot,
        })
    }

    async fn fork(&self, _snapshot: &SnapshotId, _spec: &BoxSpec) -> Result<BoxInfo> {
        Err(Error::Unsupported {
            sandbox: NAME.to_owned(),
            capability: Capability::Fork,
        })
    }

    async fn inspect(&self, id: &BoxId) -> Result<BoxInfo> {
        // Nothing external to consult: unlike a container, there is no daemon
        // holding state that could disagree with the record.
        self.store.get(id)
    }

    async fn destroy(&self, id: &BoxId) -> Result<()> {
        // The workspace belongs to the caller and is left alone; the box is the
        // record, and forgetting it is the whole of destroying it.
        self.store.remove(id)
    }
}

#[cfg(test)]
mod test;
