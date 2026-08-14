//! A sandbox backed by Docker containers.

use std::sync::Arc;

use async_trait::async_trait;
use tinybox_core::{
    BoxId, BoxInfo, BoxSpec, BoxState, Capability, Clock, Error, ExecOutput, ExecRequest, Host,
    IsolationLevel, Result, Sandbox, SandboxCapabilities, SnapshotId, SnapshotSupport, Store,
    SystemClock,
};

mod args;
mod state;

pub use args::container_name;
pub use args::{DEFAULT_BASE_IMAGE, OWNER_LABEL, WORKSPACE_MOUNT};

/// The name this sandbox registers under.
pub const NAME: &str = "docker";

/// A sandbox that runs each box as a Docker container.
///
/// # Why it drives the CLI through a [`Host`]
///
/// Every Docker operation is a `docker` command run through the sandbox's host,
/// rather than a call to a local daemon socket. That is what makes
/// Docker-on-a-remote-machine fall out of composition instead of needing a
/// socket tunnel: pair this sandbox with an SSH host and the `docker` commands
/// run over there. See ADR 0004 for the tradeoff.
///
/// # Requirements on the image
///
/// A container exits when its entrypoint returns, and an exited container
/// cannot be executed in, so each box is held open by a shell loop. Any image
/// with a `sh` works — Alpine, Debian, Ubuntu — and a distroless image does
/// not.
#[derive(Debug, Clone)]
pub struct DockerSandbox {
    host: Arc<dyn Host>,
    store: Arc<dyn Store>,
    clock: Arc<dyn Clock>,
    namespace: String,
}

/// The namespace used when a caller names none.
pub const DEFAULT_NAMESPACE: &str = "default";

impl DockerSandbox {
    /// Run containers via `docker` on `host`, recording boxes in `store`.
    ///
    /// Uses [`DEFAULT_NAMESPACE`]. Two stores on one machine that both allocate
    /// `box-0` would then fight over a container name, so anything sharing a
    /// daemon with another tinybox should use
    /// [`DockerSandbox::with_namespace`].
    #[must_use]
    pub fn new(host: Arc<dyn Host>, store: Arc<dyn Store>) -> Self {
        Self {
            host,
            store,
            clock: Arc::new(SystemClock::new()),
            namespace: DEFAULT_NAMESPACE.to_owned(),
        }
    }

    /// Read creation times from `clock` rather than the operating system.
    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// Run containers under a named namespace.
    ///
    /// Box identifiers are unique within a [`Store`]; Docker container names
    /// are unique across a daemon. The namespace is what keeps two independent
    /// stores from colliding on the same machine.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidIdentifier`] when `namespace` is empty, longer
    /// than 64 characters, or contains anything outside `[A-Za-z0-9._-]` —
    /// the same rule every tinybox identifier follows, because the namespace
    /// ends up in a container name.
    pub fn with_namespace(
        host: Arc<dyn Host>,
        store: Arc<dyn Store>,
        namespace: impl Into<String>,
    ) -> Result<Self> {
        let namespace = namespace.into();
        if !tinybox_core::identity::is_valid(&namespace) {
            return Err(Error::InvalidIdentifier {
                kind: "docker namespace",
                value: namespace,
            });
        }
        Ok(Self {
            host,
            store,
            clock: Arc::new(SystemClock::new()),
            namespace,
        })
    }

    /// The namespace this sandbox's containers are named under.
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// What this sandbox declares.
    ///
    /// `PauseResume` is absent even though `docker pause` exists, because the
    /// [`Sandbox`] trait has no method that would reach it. Declaring a
    /// capability no caller can invoke would be a claim with nothing behind it.
    ///
    /// `PortForward` **is** declared, because ports are named in the
    /// [`BoxSpec`] and applied at creation — which is the only moment a
    /// container can gain one.
    #[must_use]
    pub const fn declared_capabilities() -> SandboxCapabilities {
        SandboxCapabilities::new(IsolationLevel::Kernel, SnapshotSupport::Filesystem)
            .with_fork()
            .with_resource_limits()
            .with_port_forward()
    }

    /// Run a `docker` command, treating a non-zero exit as a failure.
    ///
    /// Unlike [`Host::run`], where a non-zero status is a result, a failing
    /// `docker` invocation means the operation did not happen — so it becomes
    /// an [`Error::Backend`] carrying Docker's own diagnostic, which is more
    /// specific than anything reconstructed here.
    async fn docker(&self, operation: &'static str, argv: Vec<String>) -> Result<String> {
        let output = self.host.run(&ExecRequest::new(argv)).await?;
        if !output.succeeded() {
            return Err(Error::Backend {
                sandbox: NAME.to_owned(),
                operation,
                message: output.stderr_lossy().trim().to_owned(),
            });
        }
        Ok(output.stdout_lossy().trim().to_owned())
    }
}

#[async_trait]
impl Sandbox for DockerSandbox {
    fn name(&self) -> &'static str {
        NAME
    }

    fn capabilities(&self) -> SandboxCapabilities {
        Self::declared_capabilities()
    }

    async fn create(&self, spec: &BoxSpec) -> Result<BoxInfo> {
        spec.validate()?;
        // Claim the record first. A container is expensive to create and has to
        // be torn down if the record cannot be written, so taking the cheap
        // resource first keeps the failure path short.
        let info =
            tinybox_core::insert_new(self.store.as_ref(), BoxState::Ready, spec, self.clock.now())?;

        // Build the command before running anything, so a source this backend
        // cannot handle leaves no container behind.
        let argv = match args::run(&self.namespace, &info.id, spec) {
            Ok(argv) => argv,
            Err(error) => {
                let _ = self.store.remove(&info.id);
                return Err(error);
            }
        };

        if let Err(error) = self.docker("create the container", argv).await {
            // No container, so the record would point at nothing.
            let _ = self.store.remove(&info.id);
            return Err(error);
        }
        Ok(info)
    }

    async fn exec(&self, id: &BoxId, request: &ExecRequest) -> Result<ExecOutput> {
        let info = self.inspect(id).await?;
        if !info.state.accepts_commands() {
            return Err(Error::InvalidState {
                id: id.as_str().to_owned(),
                actual: info.state,
                expected: BoxState::Ready,
            });
        }

        // A command that runs and fails is a result, so the raw output is
        // returned rather than being turned into a backend error.
        self.host
            .run(&ExecRequest::new(args::exec(&self.namespace, id, request)?))
            .await
    }

    async fn snapshot(&self, id: &BoxId) -> Result<SnapshotId> {
        self.capabilities()
            .require(NAME, Capability::FilesystemSnapshot)?;
        // Confirm the box exists before asking Docker, so an unknown box reads
        // as an unknown box rather than a backend complaint.
        self.store.get(id)?;

        let committed = self
            .docker("commit the container", args::commit(&self.namespace, id))
            .await?;
        args::snapshot_of_commit(&committed)
    }

    async fn fork(&self, snapshot: &SnapshotId, spec: &BoxSpec) -> Result<BoxInfo> {
        self.capabilities().require(NAME, Capability::Fork)?;

        // The snapshot is the filesystem the fork starts from, so it replaces
        // whatever source the spec named.
        let forked = spec
            .clone()
            .with_source(tinybox_core::WorkspaceSource::Snapshot(snapshot.clone()));
        self.create(&forked).await
    }

    async fn inspect(&self, id: &BoxId) -> Result<BoxInfo> {
        let mut info = self.store.get(id)?;

        // Ask Docker rather than trusting the record: a container can be
        // stopped or removed by anything with access to the daemon, and
        // reporting a stale `ready` would send commands to a box that is gone.
        let status = self
            .docker("inspect the container", args::inspect(&self.namespace, id))
            .await;
        info.state = match status {
            Ok(status) => state::from_docker(&status),
            // The record exists but the container does not, which is a real
            // state worth reporting rather than an error.
            Err(Error::Backend { .. }) => BoxState::Archived,
            Err(other) => return Err(other),
        };
        Ok(info)
    }

    async fn destroy(&self, id: &BoxId) -> Result<()> {
        // Fail on an unknown box before touching Docker.
        self.store.get(id)?;
        // Remove the container first: a record without a container is
        // recoverable, a container without a record is a leak.
        self.docker("remove the container", args::remove(&self.namespace, id))
            .await?;
        self.store.remove(id)
    }
}

#[cfg(test)]
mod test;
