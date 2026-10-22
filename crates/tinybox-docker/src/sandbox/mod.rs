//! A sandbox backed by Docker containers.

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use tinybox_core::{
    BoxId, BoxInfo, BoxSpec, BoxState, Capability, Clock, Error, ExecOutput, ExecRequest,
    ExecutionObserver, Host, IsolationLevel, OutputStream, PortMapping, ProcessId, Result, Sandbox,
    SandboxCapabilities, SnapshotId, SnapshotSupport, Store, SystemClock, detach,
};

mod args;
mod observed;
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
    failed_create_attempts: Arc<std::sync::Mutex<HashMap<BoxId, String>>>,
    pending_observed_cleanup: Arc<Mutex<HashMap<String, CleanupHandle>>>,
    observed_boxes: Arc<Mutex<HashMap<BoxId, ObservedBoxState>>>,
}

#[derive(Debug, Clone)]
struct CleanupHandle {
    id: BoxId,
    token: String,
    generation: u64,
    launched: bool,
    acknowledged: Arc<AtomicBool>,
    unsupported: Arc<AtomicBool>,
}

#[derive(Debug, Default)]
struct ObservedBoxState {
    generation: u64,
    destroyed: bool,
}

#[derive(Debug, Default)]
struct ObservedControl {
    acknowledged: AtomicBool,
    unsupported: AtomicBool,
}

#[derive(Debug)]
struct RetainCleanupOnDrop {
    observed_boxes: Arc<Mutex<HashMap<BoxId, ObservedBoxState>>>,
    pending: Arc<Mutex<HashMap<String, CleanupHandle>>>,
    handle: CleanupHandle,
    armed: bool,
}

impl RetainCleanupOnDrop {
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for RetainCleanupOnDrop {
    fn drop(&mut self) {
        if self.armed {
            retain_observed_cleanup(&self.observed_boxes, &self.pending, self.handle.clone());
        }
    }
}

struct DockerExecutionObserver {
    inner: Arc<dyn ExecutionObserver>,
    host: Arc<dyn Host>,
    namespace: String,
    handle: CleanupHandle,
    observed_boxes: Arc<Mutex<HashMap<BoxId, ObservedBoxState>>>,
    pending: Arc<Mutex<HashMap<String, CleanupHandle>>>,
    control: Arc<ObservedControl>,
}

impl std::fmt::Debug for DockerExecutionObserver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DockerExecutionObserver")
            .field("box_id", &self.handle.id)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl ExecutionObserver for DockerExecutionObserver {
    fn output(&self, stream: OutputStream, bytes: &[u8]) -> Result<()> {
        self.inner.output(stream, bytes)
    }

    async fn cancelled(&self) {
        self.inner.cancelled().await;
        match cleanup_remote(self.host.clone(), &self.namespace, &self.handle).await {
            Ok(unsupported) => {
                self.control
                    .unsupported
                    .store(unsupported, Ordering::Release);
                self.control.acknowledged.store(true, Ordering::Release);
            }
            Err(_) => {
                retain_observed_cleanup(&self.observed_boxes, &self.pending, self.handle.clone());
            }
        }
    }
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
            failed_create_attempts: Arc::default(),
            pending_observed_cleanup: Arc::default(),
            observed_boxes: Arc::default(),
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
            failed_create_attempts: Arc::default(),
            pending_observed_cleanup: Arc::default(),
            observed_boxes: Arc::default(),
        })
    }

    /// Route observed execution through a per-operation host while preserving
    /// this sandbox's container identity and store.
    ///
    /// The returned view uses the same namespace, clock, box records, and
    /// failed-create ownership as this sandbox, so an existing [`BoxId`] still
    /// names the same container. Its observed-cleanup journal is private to the
    /// view; cancelling one operation therefore cannot drain another view's
    /// pending cleanup. This is intended for dispatching an existing observed
    /// operation and must not be used to create or destroy a box through a
    /// different host.
    #[must_use]
    pub fn for_observed_host(&self, host: Arc<dyn Host>) -> Self {
        Self {
            host,
            store: self.store.clone(),
            clock: self.clock.clone(),
            namespace: self.namespace.clone(),
            failed_create_attempts: self.failed_create_attempts.clone(),
            pending_observed_cleanup: Arc::default(),
            observed_boxes: self.observed_boxes.clone(),
        }
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
    ///
    /// `Detach` is declared because a container is a running machine between
    /// commands: `args::run` starts it with `--detach` and a keepalive, so a
    /// backgrounded process and the pid file naming it are both still there on
    /// the next `docker exec`.
    #[must_use]
    pub const fn declared_capabilities() -> SandboxCapabilities {
        SandboxCapabilities::new(IsolationLevel::Kernel, SnapshotSupport::Filesystem)
            .with_fork()
            .with_port_forward()
            .with_detach()
    }

    /// Run a `docker` command, treating a non-zero exit as a failure.
    ///
    /// Unlike [`Host::run`], where a non-zero status is a result, a failing
    /// `docker` invocation is an operation error — so it becomes an
    /// [`Error::Backend`] carrying Docker's own diagnostic, which is more
    /// specific than anything reconstructed here. A remote daemon may have
    /// completed a create before its response was lost, so callers reconcile
    /// that case by checking the created container's ownership label.
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

    /// Remove a named container, treating Docker's explicit missing-container
    /// response as an already-completed cleanup.
    async fn remove_container(&self, argv: Vec<String>) -> Result<()> {
        let output = self.host.run(&ExecRequest::new(argv)).await?;
        if output.succeeded() || output.stderr_lossy().contains("No such container") {
            return Ok(());
        }
        Err(Error::Backend {
            sandbox: NAME.to_owned(),
            operation: "remove the container",
            message: output.stderr_lossy().trim().to_owned(),
        })
    }

    fn discard_failed_create_record(&self, id: &BoxId, attempt: &str) {
        if self.store.remove(id).is_err() {
            self.failed_create_attempts
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(id.clone(), attempt.to_owned());
        }
    }

    fn remember_observed_cleanup(&self, handle: CleanupHandle) -> bool {
        retain_observed_cleanup(&self.observed_boxes, &self.pending_observed_cleanup, handle)
    }

    fn observed_generation_for_exec(&self, id: &BoxId) -> Result<u64> {
        let mut boxes = lock(&self.observed_boxes);
        let state = boxes.entry(id.clone()).or_default();
        if state.destroyed {
            return Err(Error::InvalidState {
                id: id.as_str().to_owned(),
                actual: BoxState::Archived,
                expected: BoxState::Ready,
            });
        }
        Ok(state.generation)
    }

    fn mark_observed_box_created(&self, id: &BoxId) {
        let mut boxes = lock(&self.observed_boxes);
        let state = boxes.entry(id.clone()).or_default();
        state.generation = state.generation.wrapping_add(1);
        state.destroyed = false;
    }

    fn mark_observed_box_destroyed(&self, id: &BoxId) {
        let mut boxes = lock(&self.observed_boxes);
        let state = boxes.entry(id.clone()).or_default();
        state.generation = state.generation.wrapping_add(1);
        state.destroyed = true;
        lock(&self.pending_observed_cleanup).retain(|_, handle| &handle.id != id);
    }

    fn observed_handle_is_current(&self, handle: &CleanupHandle) -> bool {
        let boxes = lock(&self.observed_boxes);
        boxes
            .get(&handle.id)
            .is_none_or(|state| !state.destroyed && state.generation == handle.generation)
    }

    fn clear_observed_cleanup(&self, token: &str) {
        lock(&self.pending_observed_cleanup).remove(token);
    }

    fn pending_observed_handles(&self) -> Vec<CleanupHandle> {
        lock(&self.pending_observed_cleanup)
            .values()
            .cloned()
            .collect()
    }

    async fn reserve_observed_execution(&self, handle: &CleanupHandle) -> Result<()> {
        match reserve_remote(self.host.clone(), &self.namespace, handle).await {
            Ok(()) => Ok(()),
            Err(reserve_error) => {
                self.cleanup_or_retain(handle.clone()).await?;
                Err(reserve_error)
            }
        }
    }

    async fn cleanup_or_retain(&self, handle: CleanupHandle) -> Result<bool> {
        if let Ok(unsupported) = cleanup_remote(self.host.clone(), &self.namespace, &handle).await {
            Ok(unsupported)
        } else if self.remember_observed_cleanup(handle) {
            Err(Error::ObservedCleanupPending {
                provider: NAME.to_owned(),
            })
        } else {
            Ok(false)
        }
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

    fn constraint_support(&self) -> tinybox_core::ConstraintSupport {
        use tinybox_core::Constraint::{Cpu, Filesystem, Memory, Network, Pids};
        use tinybox_core::Enforcement::Enforced;
        tinybox_core::ConstraintSupport::NONE
            .with(Filesystem, Enforced)
            .with(Network, Enforced)
            .with(Cpu, Enforced)
            .with(Memory, Enforced)
            .with(Pids, Enforced)
    }

    async fn create(&self, spec: &BoxSpec) -> Result<BoxInfo> {
        spec.validate()?;
        spec.network.refuse_allowlist(self.name())?;
        // The workspace is bind-mounted read-write, so it gets the one-shot
        // mount policy before any record or container exists.
        // ponytail: through an SSH host the daemon's filesystem is remote, so
        // only the lexical checks apply; resolve on that host if it matters.
        if let tinybox_core::WorkspaceSource::LocalDir(path) = &spec.source
            && path.to_str().is_none_or(crate::policy::is_dangerous_mount)
        {
            return Err(Error::UnsupportedWorkspaceSource {
                sandbox: NAME.to_owned(),
                kind: "dangerous host directory",
            });
        }
        let attempt = uuid::Uuid::new_v4().to_string();
        // Claim the record first. A container is expensive to create and has to
        // be torn down if the record cannot be written, so taking the cheap
        // resource first keeps the failure path short.
        let info =
            tinybox_core::insert_new(self.store.as_ref(), BoxState::Ready, spec, self.clock.now())?;

        // Build the command before running anything, so a source this backend
        // cannot handle leaves no container behind.
        let argv = match args::run(&self.namespace, &info.id, &attempt, spec) {
            Ok(argv) => argv,
            Err(error) => {
                self.discard_failed_create_record(&info.id, &attempt);
                return Err(error);
            }
        };

        if let Err(error) = self.docker("create the container", argv).await {
            // Docker reports a name collision before creating a container.
            // Never remove that name: it belongs to the pre-existing owner.
            if is_name_conflict(&error) {
                self.discard_failed_create_record(&info.id, &attempt);
                return Err(error);
            }

            // A lost response can hide a successful create. Reconcile only
            // after the daemon confirms this exact attempt token; otherwise a
            // deterministic name may refer to another store's container with
            // the same box id.
            match self
                .docker(
                    "inspect the failed create",
                    args::inspect_attempt(&self.namespace, &info.id),
                )
                .await
            {
                Ok(owner) if owner == attempt => {
                    if self
                        .remove_container(args::remove(&self.namespace, &info.id))
                        .await
                        .is_ok()
                    {
                        self.discard_failed_create_record(&info.id, &attempt);
                    } else {
                        self.failed_create_attempts
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .insert(info.id.clone(), attempt);
                    }
                }
                Ok(_) => {
                    self.discard_failed_create_record(&info.id, &attempt);
                }
                Err(Error::Backend { message, .. }) if message.contains("No such container") => {
                    self.discard_failed_create_record(&info.id, &attempt);
                }
                Err(_) => {
                    self.failed_create_attempts
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .insert(info.id.clone(), attempt);
                }
            }
            return Err(error);
        }
        self.failed_create_attempts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&info.id);
        self.mark_observed_box_created(&info.id);
        Ok(info)
    }

    async fn spawn(&self, id: &BoxId, request: &ExecRequest) -> Result<ProcessId> {
        let process = detach::mint();
        let output = self.exec(id, &detach::start(&process, request)?).await?;
        if !output.succeeded() {
            return Err(Error::Backend {
                sandbox: NAME.to_owned(),
                operation: "start a detached process",
                message: output.stderr_lossy().trim().to_owned(),
            });
        }
        Ok(process)
    }

    async fn is_running(&self, id: &BoxId, process: &ProcessId) -> Result<bool> {
        let output = self.exec(id, &detach::probe(process)).await?;
        Ok(output.stdout_lossy().trim() == detach::RUNNING)
    }

    async fn stop(&self, id: &BoxId, process: &ProcessId) -> Result<()> {
        let output = self
            .exec(id, &detach::stop(process, detach::DEFAULT_GRACE))
            .await?;
        if !output.succeeded() {
            return Err(Error::Backend {
                sandbox: NAME.to_owned(),
                operation: "stop a detached process",
                message: output.stderr_lossy().trim().to_owned(),
            });
        }
        Ok(())
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

    async fn exec_observed(
        &self,
        id: &BoxId,
        request: &ExecRequest,
        observer: Arc<dyn ExecutionObserver>,
    ) -> Result<ExecOutput> {
        let info = self.inspect(id).await?;
        if !info.state.accepts_commands() {
            return Err(Error::InvalidState {
                id: id.as_str().to_owned(),
                actual: info.state,
                expected: BoxState::Ready,
            });
        }

        let generation = self.observed_generation_for_exec(id)?;
        let handle = CleanupHandle {
            id: id.clone(),
            token: uuid::Uuid::new_v4().simple().to_string(),
            generation,
            launched: false,
            acknowledged: Arc::default(),
            unsupported: Arc::default(),
        };
        let observed_request = observed::exec(&self.namespace, id, request, &handle.token)?;
        let mut retain_on_drop = RetainCleanupOnDrop {
            observed_boxes: self.observed_boxes.clone(),
            pending: self.pending_observed_cleanup.clone(),
            handle: handle.clone(),
            armed: true,
        };
        if let Err(error) = self.reserve_observed_execution(&handle).await {
            retain_on_drop.disarm();
            return Err(error);
        }
        let handle = CleanupHandle {
            launched: true,
            ..handle
        };
        retain_on_drop.handle = handle.clone();
        let control = Arc::new(ObservedControl::default());
        let observer = Arc::new(DockerExecutionObserver {
            inner: observer,
            host: self.host.clone(),
            namespace: self.namespace.clone(),
            handle: handle.clone(),
            observed_boxes: self.observed_boxes.clone(),
            pending: self.pending_observed_cleanup.clone(),
            control: control.clone(),
        });

        let result = self.host.run_observed(&observed_request, observer).await;

        if matches!(&result, Err(Error::UnsupportedStreaming { .. })) {
            let reservation = CleanupHandle {
                launched: false,
                ..handle.clone()
            };
            if self.cleanup_or_retain(reservation).await.is_err() {
                retain_on_drop.disarm();
                return Err(Error::ObservedCleanupPending {
                    provider: NAME.to_owned(),
                });
            }
            retain_on_drop.disarm();
            return result;
        }
        if control.unsupported.load(Ordering::Acquire) {
            retain_on_drop.disarm();
            return Err(Error::UnsupportedStreaming {
                provider: NAME.to_owned(),
            });
        }
        if lock(&self.pending_observed_cleanup).contains_key(&handle.token) {
            return Err(Error::ObservedCleanupPending {
                provider: NAME.to_owned(),
            });
        }

        if !control.acknowledged.load(Ordering::Acquire) {
            if let Ok(unsupported) =
                cleanup_remote(self.host.clone(), &self.namespace, &handle).await
            {
                control.unsupported.store(unsupported, Ordering::Release);
                control.acknowledged.store(true, Ordering::Release);
            } else if self.remember_observed_cleanup(handle) {
                return Err(Error::ObservedCleanupPending {
                    provider: NAME.to_owned(),
                });
            }
        }

        retain_on_drop.disarm();
        if control.unsupported.load(Ordering::Acquire) {
            return Err(Error::UnsupportedStreaming {
                provider: NAME.to_owned(),
            });
        }
        result
    }

    fn has_pending_observed_cleanup(&self) -> bool {
        self.host.has_pending_observed_cleanup() || !lock(&self.pending_observed_cleanup).is_empty()
    }

    fn acknowledge_observed_cleanup_for_destroyed_box(&self, id: &BoxId) {
        lock(&self.pending_observed_cleanup).retain(|_, handle| &handle.id != id);
    }

    async fn retry_observed_cleanup(&self) -> Result<()> {
        let host_result = self.host.retry_observed_cleanup().await;
        let handles = self.pending_observed_handles();
        let mut failed = false;
        for handle in handles {
            if !self.observed_handle_is_current(&handle) {
                self.clear_observed_cleanup(&handle.token);
                continue;
            }
            match cleanup_remote(self.host.clone(), &self.namespace, &handle).await {
                Err(_) if self.observed_handle_is_current(&handle) => failed = true,
                _ => self.clear_observed_cleanup(&handle.token),
            }
        }
        if failed {
            Err(Error::ObservedCleanupPending {
                provider: NAME.to_owned(),
            })
        } else {
            host_result
        }
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

    async fn published_ports(&self, id: &BoxId) -> Result<Vec<PortMapping>> {
        let output = self
            .docker(
                "inspect published container ports",
                args::published_ports(&self.namespace, id),
            )
            .await?;
        args::parse_published_ports(&output)
    }

    async fn destroy(&self, id: &BoxId) -> Result<()> {
        // Fail on an unknown box before touching Docker.
        self.store.get(id)?;
        let attempt = self
            .failed_create_attempts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(id)
            .cloned();
        if let Some(attempt) = attempt {
            let owner = self
                .docker(
                    "inspect the failed create",
                    args::inspect_attempt(&self.namespace, id),
                )
                .await;
            match owner {
                Ok(owner) if owner == attempt => {}
                Err(Error::Backend { message, .. }) if message.contains("No such container") => {}
                Ok(_) => {
                    return Err(Error::Backend {
                        sandbox: NAME.to_owned(),
                        operation: "verify failed container ownership",
                        message: "container belongs to another create attempt".to_owned(),
                    });
                }
                Err(error) => return Err(error),
            }
        }
        // Remove the container first: a record without a container is
        // recoverable, a container without a record is a leak.
        self.remove_container(args::remove(&self.namespace, id))
            .await?;
        self.mark_observed_box_destroyed(id);
        self.acknowledge_observed_cleanup_for_destroyed_box(id);
        self.store.remove(id)?;
        self.failed_create_attempts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(id);
        Ok(())
    }
}

fn is_name_conflict(error: &Error) -> bool {
    matches!(error, Error::Backend { message, .. }
        if message.contains("container name") && message.contains("already in use"))
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn retain_observed_cleanup(
    observed_boxes: &Mutex<HashMap<BoxId, ObservedBoxState>>,
    pending: &Mutex<HashMap<String, CleanupHandle>>,
    handle: CleanupHandle,
) -> bool {
    let boxes = lock(observed_boxes);
    let is_current = boxes
        .get(&handle.id)
        .is_none_or(|state| !state.destroyed && state.generation == handle.generation);
    if is_current {
        lock(pending).insert(handle.token.clone(), handle);
    }
    is_current
}

async fn cleanup_remote(
    host: Arc<dyn Host>,
    namespace: &str,
    handle: &CleanupHandle,
) -> Result<bool> {
    if !handle.launched {
        reserve_remote(host.clone(), namespace, handle).await?;
        let request = observed::abort_reservation(namespace, &handle.id, &handle.token);
        let output = tokio::time::timeout(Duration::from_secs(8), host.run(&request))
            .await
            .map_err(|_| cleanup_timeout_error())??;
        if !output.succeeded() {
            return Err(Error::Backend {
                sandbox: NAME.to_owned(),
                operation: "release unstarted observed execution reservation",
                message: output.stderr_lossy().trim().to_owned(),
            });
        }
        return Ok(false);
    }
    if handle.acknowledged.load(Ordering::Acquire) {
        release_receipt(host, namespace, handle).await?;
        return Ok(handle.unsupported.load(Ordering::Acquire));
    }
    let request = observed::cancel_and_ack(namespace, &handle.id, &handle.token);
    let output = tokio::time::timeout(Duration::from_secs(8), host.run(&request))
        .await
        .map_err(|_| cleanup_timeout_error())??;
    if !output.succeeded() {
        return Err(Error::Backend {
            sandbox: NAME.to_owned(),
            operation: "acknowledge observed execution cleanup",
            message: output.stderr_lossy().trim().to_owned(),
        });
    }
    let unsupported = output.stdout_lossy().trim() == "unsupported";
    handle.unsupported.store(unsupported, Ordering::Release);
    handle.acknowledged.store(true, Ordering::Release);
    release_receipt(host, namespace, handle).await?;
    Ok(unsupported)
}

async fn release_receipt(
    host: Arc<dyn Host>,
    namespace: &str,
    handle: &CleanupHandle,
) -> Result<()> {
    let request = observed::release_receipt(namespace, &handle.id, &handle.token);
    let output = tokio::time::timeout(Duration::from_secs(8), host.run(&request))
        .await
        .map_err(|_| Error::Backend {
            sandbox: NAME.to_owned(),
            operation: "release acknowledged observed execution receipt",
            message: "container-side receipt release was not confirmed before the deadline"
                .to_owned(),
        })??;
    if !output.succeeded() {
        return Err(Error::Backend {
            sandbox: NAME.to_owned(),
            operation: "release acknowledged observed execution receipt",
            message: output.stderr_lossy().trim().to_owned(),
        });
    }
    Ok(())
}

async fn reserve_remote(
    host: Arc<dyn Host>,
    namespace: &str,
    handle: &CleanupHandle,
) -> Result<()> {
    let request = observed::reserve(namespace, &handle.id, &handle.token);
    let output = tokio::time::timeout(Duration::from_secs(8), host.run(&request))
        .await
        .map_err(|_| Error::Backend {
            sandbox: NAME.to_owned(),
            operation: "reserve observed execution control directory",
            message: "container did not confirm its execution reservation before the deadline"
                .to_owned(),
        })??;
    if !output.succeeded() || output.stdout_lossy().trim() != "ready" {
        return Err(Error::Backend {
            sandbox: NAME.to_owned(),
            operation: "reserve observed execution control directory",
            message: output.stderr_lossy().trim().to_owned(),
        });
    }
    Ok(())
}

fn cleanup_timeout_error() -> Error {
    Error::Backend {
        sandbox: NAME.to_owned(),
        operation: "acknowledge observed execution cleanup",
        message: "container-side waiter did not acknowledge cleanup before the deadline".to_owned(),
    }
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod test;
