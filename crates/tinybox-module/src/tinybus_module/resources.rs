//! Module-owned sandbox and detached-process lifetimes.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tinybox_bus::{
    CreateRequest, ExecOutput, ExecRequest, ProcessRef, ReserveRequest, ResourceId, ResourceInfo,
    SpawnRequest, Workspace,
};
use tinybox_core::clock::{Clock, SystemClock};
use tinybox_core::{
    BoxId, BoxSpec, HostRef, MemoryStore, Placement, ProcessId, Sandbox, SandboxRef,
    WorkspaceSource,
};
use tinybus::{Error, Result};
use tokio::sync::Mutex;

struct Resource {
    sandbox: Arc<dyn Sandbox>,
    id: BoxId,
    processes: BTreeMap<ResourceId, OwnedProcess>,
    local_sandbox: Option<Arc<tinybox_core::PassthroughSandbox>>,
    collector: Option<Arc<tinybox_host::LimitedLocalHost>>,
}

enum OwnedProcess {
    Native(tinybox_host::ManagedProcess),
    Sandbox { id: ProcessId, stopped: bool },
}

#[cfg(test)]
impl OwnedProcess {
    fn is_running(&self) -> bool {
        match self {
            Self::Native(process) => process.is_running(),
            Self::Sandbox { stopped, .. } => !stopped,
        }
    }
}

/// Registry owned by one module instance; close and operations are serialized.
pub(super) struct Resources {
    instance: String,
    clock: Arc<dyn Clock>,
    finished: tokio::sync::Notify,
    state: Mutex<State>,
    executions: std::sync::Mutex<Executions>,
}

#[derive(Default)]
struct State {
    entries: BTreeMap<ResourceId, Arc<Mutex<Option<Resource>>>>,
    reservations: BTreeMap<ResourceId, (ReserveRequest, std::time::SystemTime)>,
    pending_processes: BTreeMap<ResourceId, (ResourceId, Arc<AtomicBool>)>,
    next: u64,
    shutdown: bool,
}

#[derive(Default)]
struct Executions {
    closing: BTreeSet<ResourceId>,
    native: BTreeMap<ResourceId, tokio::task::AbortHandle>,
}

impl Default for Resources {
    fn default() -> Self {
        Self {
            instance: uuid::Uuid::new_v4().to_string(),
            clock: Arc::new(SystemClock::new()),
            finished: tokio::sync::Notify::new(),
            state: Mutex::default(),
            executions: std::sync::Mutex::default(),
        }
    }
}

impl Resources {
    pub(super) async fn reserve(&self, request: ReserveRequest) -> Result<ResourceId> {
        let mut state = self.state.lock().await;
        if state.shutdown {
            return Err(failure(tinybox_bus::EXEC_CANCELLED, "module is shut down"));
        }
        let now = self.clock.now();
        state.reservations.retain(|_, (_, issued)| {
            now.duration_since(*issued).unwrap_or_default().as_secs()
                < tinybox_bus::RESERVATION_TTL_SECS
        });
        if state.reservations.len() >= tinybox_bus::MAX_RESERVATIONS {
            return Err(failure(
                tinybox_bus::RESOURCE_LIMIT,
                "idle reservation limit reached",
            ));
        }
        if let ReserveRequest::Process(resource) = &request
            && !state.entries.contains_key(resource)
        {
            return Err(failure(tinybox_bus::UNKNOWN_RESOURCE, "unknown resource"));
        }
        state.next = state.next.checked_add(1).ok_or_else(|| {
            failure(
                tinybox_bus::RESOURCE_LIMIT,
                "reservation sequence exhausted",
            )
        })?;
        let id = ResourceId(format!("{}-{}", self.instance, state.next));
        state.reservations.insert(id.clone(), (request, now));
        Ok(id)
    }

    fn consume(&self, state: &mut State, id: &ResourceId, expected: &ReserveRequest) -> Result<()> {
        validate_id(id)?;
        if state.shutdown {
            return Err(failure(tinybox_bus::EXEC_CANCELLED, "module is shut down"));
        }
        let Some((kind, issued)) = state.reservations.get(id) else {
            return Err(failure(
                tinybox_bus::DUPLICATE_ID,
                "reservation is consumed, expired, or unknown",
            ));
        };
        if kind != expected {
            return Err(failure(
                tinybox_bus::INVALID_ID,
                "reservation belongs to another target",
            ));
        }
        let expired = self
            .clock
            .now()
            .duration_since(*issued)
            .unwrap_or_default()
            .as_secs()
            >= tinybox_bus::RESERVATION_TTL_SECS;
        state.reservations.remove(id);
        if expired {
            return Err(failure(tinybox_bus::DUPLICATE_ID, "reservation expired"));
        }
        Ok(())
    }

    pub(super) async fn create(&self, request: CreateRequest) -> Result<ResourceInfo> {
        let host = Arc::new(tinybox_host::LimitedLocalHost::new(
            tinybox_bus::MAX_OUTPUT_BYTES,
        ));
        self.create_with(request, host.clone(), Some(host)).await
    }

    #[cfg(test)]
    async fn create_on(
        &self,
        request: CreateRequest,
        host: Arc<dyn tinybox_core::Host>,
    ) -> Result<ResourceInfo> {
        self.create_with(request, host, None).await
    }

    async fn create_with(
        &self,
        request: CreateRequest,
        host: Arc<dyn tinybox_core::Host>,
        collector: Option<Arc<tinybox_host::LimitedLocalHost>>,
    ) -> Result<ResourceInfo> {
        let slot = Arc::new(Mutex::new(None));
        {
            let mut state = self.state.lock().await;
            self.consume(&mut state, &request.resource, &ReserveRequest::Resource)?;
            if state.entries.len() >= tinybox_bus::MAX_ACTIVE_RESOURCES {
                return Err(failure(
                    tinybox_bus::RESOURCE_LIMIT,
                    "active resource limit reached",
                ));
            }
            state.entries.insert(request.resource.clone(), slot.clone());
        }
        let mut slot = slot.lock().await;
        let allocation = async {
            if self
                .executions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .closing
                .contains(&request.resource)
            {
                return Err(failure(tinybox_bus::EXEC_CANCELLED, "resource is closing"));
            }
            let store = Arc::new(MemoryStore::new());
            let mut local_sandbox = None;
            let sandbox: Arc<dyn Sandbox> = match request.backend.as_str() {
                "passthrough" => {
                    let sandbox =
                        Arc::new(tinybox_core::PassthroughSandbox::new(host, store.clone()));
                    local_sandbox = Some(sandbox.clone());
                    sandbox
                }
                "docker" => Arc::new(tinybox_docker::DockerSandbox::new(host, store.clone())),
                "namespace" => Arc::new(tinybox_linux::NamespaceSandbox::new(host, store.clone())),
                _ => {
                    return Err(failure(
                        tinybox_bus::UNSUPPORTED_BACKEND,
                        "unsupported sandbox backend",
                    ));
                }
            };
            let source = match request.workspace {
                Workspace::Directory(path) => WorkspaceSource::LocalDir(path.into()),
                Workspace::Image(image) => WorkspaceSource::OciImage(image),
            };
            let placement = Placement::new(
                HostRef::new("local").map_err(|error| backend_error(&error))?,
                SandboxRef::new(&request.backend).map_err(|error| backend_error(&error))?,
            );
            let mut spec = BoxSpec::new(placement, source);
            spec.env = request.env;
            let info = match sandbox.create(&spec).await {
                Ok(info) => info,
                Err(error) => {
                    // Docker may have created the named container even if its
                    // reply was lost. The backend retains its store record only
                    // when named cleanup failed; keep the sandbox and id in
                    // this caller-known slot so Close/Shutdown can retry it.
                    if request.backend == "docker"
                        && let Ok(records) = tinybox_core::Store::list(store.as_ref())
                        && let Some(info) = records.into_iter().next()
                    {
                        *slot = Some(Resource {
                            sandbox,
                            id: info.id,
                            processes: BTreeMap::new(),
                            collector,
                            local_sandbox,
                        });
                    }
                    return Err(backend_error(&error));
                }
            };
            let result = ResourceInfo {
                resource: request.resource.clone(),
                backend: request.backend,
                state: info.state.to_string(),
            };
            *slot = Some(Resource {
                sandbox,
                id: info.id,
                processes: BTreeMap::new(),
                collector,
                local_sandbox,
            });
            if self.state.lock().await.shutdown {
                return Err(failure(
                    tinybox_bus::EXEC_CANCELLED,
                    "module shut down during startup",
                ));
            }
            Ok(result)
        }
        .await;
        if allocation.is_err() && slot.is_none() {
            self.state.lock().await.entries.remove(&request.resource);
        }
        allocation
    }

    async fn slot(&self, resource: &ResourceId) -> Result<Arc<Mutex<Option<Resource>>>> {
        self.state
            .lock()
            .await
            .entries
            .get(resource)
            .cloned()
            .ok_or_else(|| failure(tinybox_bus::UNKNOWN_RESOURCE, "unknown resource"))
    }

    pub(super) async fn inspect(&self, resource: &ResourceId) -> Result<ResourceInfo> {
        let slot = self.slot(resource).await?;
        let slot = slot.lock().await;
        let entry = slot
            .as_ref()
            .ok_or_else(|| failure(tinybox_bus::UNKNOWN_RESOURCE, "closed resource"))?;
        let info = entry
            .sandbox
            .inspect(&entry.id)
            .await
            .map_err(|error| backend_error(&error))?;
        Ok(ResourceInfo {
            resource: resource.clone(),
            backend: entry.sandbox.name().to_owned(),
            state: info.state.to_string(),
        })
    }

    pub(super) async fn exec(&self, request: ExecRequest) -> Result<ExecOutput> {
        let slot = self.slot(&request.resource).await?;
        let slot = slot.lock().await;
        let entry = slot
            .as_ref()
            .ok_or_else(|| failure(tinybox_bus::UNKNOWN_RESOURCE, "closed resource"))?;
        let resource = request.resource.clone();
        if entry.collector.is_some()
            && entry.local_sandbox.is_none()
            && entry.sandbox.name() != tinybox_docker::NAME
        {
            return Err(failure(
                tinybox_bus::UNSUPPORTED_OPERATION,
                "module Exec requires supervised local passthrough ownership",
            ));
        }
        let sandbox = entry.sandbox.clone();
        let id = entry.id.clone();
        let command = command(request);
        let native = {
            let mut executions = self
                .executions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if executions.closing.contains(&resource) {
                return Err(failure(tinybox_bus::EXEC_CANCELLED, "resource is closing"));
            }
            let task = tokio::spawn(async move { sandbox.exec(&id, &command).await });
            executions
                .native
                .insert(resource.clone(), task.abort_handle());
            task
        };
        let outcome = native.await;
        self.executions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .native
            .remove(&resource);
        let output = outcome
            .map_err(|error| failure(tinybox_bus::EXEC_CANCELLED, &error.to_string()))?
            .map_err(|error| backend_error(&error))?;
        Ok(ExecOutput {
            exit_code: output.exit_code,
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }

    pub(super) async fn spawn(&self, request: SpawnRequest) -> Result<ProcessRef> {
        let cancelled = Arc::new(AtomicBool::new(false));
        {
            let mut state = self.state.lock().await;
            self.consume(
                &mut state,
                &request.process,
                &ReserveRequest::Process(request.command.resource.clone()),
            )?;
            if state
                .pending_processes
                .values()
                .filter(|(resource, _)| resource == &request.command.resource)
                .count()
                >= tinybox_bus::MAX_PROCESSES_PER_RESOURCE
            {
                return Err(failure(
                    tinybox_bus::RESOURCE_LIMIT,
                    "pending process limit reached",
                ));
            }
            state.pending_processes.insert(
                request.process.clone(),
                (request.command.resource.clone(), cancelled.clone()),
            );
        }
        let result = self.spawn_pending(request.clone(), cancelled).await;
        self.state
            .lock()
            .await
            .pending_processes
            .remove(&request.process);
        self.finished.notify_waiters();
        result
    }

    async fn spawn_pending(
        &self,
        request: SpawnRequest,
        cancelled: Arc<AtomicBool>,
    ) -> Result<ProcessRef> {
        let slot = self.slot(&request.command.resource).await?;
        let mut slot = slot.lock().await;
        let entry = slot
            .as_mut()
            .ok_or_else(|| failure(tinybox_bus::UNKNOWN_RESOURCE, "closed resource"))?;
        if entry.processes.len() >= tinybox_bus::MAX_PROCESSES_PER_RESOURCE {
            return Err(failure(
                tinybox_bus::RESOURCE_LIMIT,
                "process reservation limit reached",
            ));
        }
        if cancelled.load(Ordering::SeqCst) {
            return Err(failure(
                tinybox_bus::EXEC_CANCELLED,
                "process startup cancelled",
            ));
        }
        let resource = request.command.resource.clone();
        if let Some(local) = entry.local_sandbox.as_ref() {
            let collector = entry.collector.as_ref().ok_or_else(|| {
                failure(
                    tinybox_bus::UNSUPPORTED_OPERATION,
                    "module Spawn requires the owned local collector",
                )
            })?;
            let resolved = local
                .resolve_command(&entry.id, &command(request.command))
                .map_err(|error| backend_error(&error))?;
            let native = collector
                .spawn(&resolved)
                .map_err(|error| backend_error(&error))?;
            entry
                .processes
                .insert(request.process.clone(), OwnedProcess::Native(native));
        } else if entry.sandbox.name() == tinybox_docker::NAME {
            let process_id =
                ProcessId::new(request.process.0.clone()).map_err(|error| backend_error(&error))?;
            let start = tinybox_core::detach::start(&process_id, &command(request.command))
                .map_err(|error| backend_error(&error))?;
            entry.processes.insert(
                request.process.clone(),
                OwnedProcess::Sandbox {
                    id: process_id,
                    stopped: false,
                },
            );
            let started = entry.sandbox.exec(&entry.id, &start).await;
            let startup = started
                .map_err(|error| backend_error(&error))
                .and_then(|output| {
                    if output.succeeded() {
                        Ok(())
                    } else {
                        Err(backend_error(&tinybox_core::Error::Backend {
                            sandbox: tinybox_docker::NAME.into(),
                            operation: "start a detached process",
                            message: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
                        }))
                    }
                });
            if cancelled.load(Ordering::SeqCst) || startup.is_err() {
                if let Some(process) = entry.processes.get_mut(&request.process)
                    && stop_process(&entry.sandbox, &entry.id, process)
                        .await
                        .is_ok()
                {
                    entry.processes.remove(&request.process);
                }
                if cancelled.load(Ordering::SeqCst) {
                    return Err(failure(
                        tinybox_bus::EXEC_CANCELLED,
                        "process startup cancelled",
                    ));
                }
                startup?;
            }
        } else {
            return Err(failure(
                tinybox_bus::UNSUPPORTED_OPERATION,
                "module Spawn requires a backend with owned process cleanup",
            ));
        }
        Ok(ProcessRef {
            resource,
            process: request.process,
        })
    }

    pub(super) async fn is_running(&self, process: &ProcessRef) -> Result<bool> {
        let slot = self.slot(&process.resource).await?;
        let mut slot = slot.lock().await;
        let entry = slot
            .as_mut()
            .ok_or_else(|| failure(tinybox_bus::UNKNOWN_RESOURCE, "closed resource"))?;
        let Some(native) = entry.processes.get_mut(&process.process) else {
            validate_id(&process.process)?;
            return Ok(false);
        };
        let running = match native {
            OwnedProcess::Native(native) => native.is_running(),
            OwnedProcess::Sandbox { id, .. } => entry
                .sandbox
                .is_running(&entry.id, id)
                .await
                .map_err(|error| backend_error(&error))?,
        };
        if !running {
            let result = stop_process(&entry.sandbox, &entry.id, native).await;
            if result.is_ok() {
                entry.processes.remove(&process.process);
            }
            result?;
        }
        Ok(running)
    }

    pub(super) async fn cancel(&self, process: &ProcessRef) -> Result<()> {
        {
            let mut state = self.state.lock().await;
            validate_id(&process.process)?;
            if let Some((kind, _)) = state.reservations.get(&process.process) {
                if kind != &ReserveRequest::Process(process.resource.clone()) {
                    return Err(failure(
                        tinybox_bus::INVALID_ID,
                        "reservation belongs to another target",
                    ));
                }
                state.reservations.remove(&process.process);
            }
            if let Some((resource, cancelled)) = state.pending_processes.get(&process.process) {
                if resource != &process.resource {
                    return Err(failure(
                        tinybox_bus::INVALID_ID,
                        "pending process belongs to another target",
                    ));
                }
                cancelled.store(true, Ordering::SeqCst);
            }
        }
        let Ok(slot) = self.slot(&process.resource).await else {
            return Ok(());
        };
        let mut slot = slot.lock().await;
        let Some(entry) = slot.as_mut() else {
            return Ok(());
        };
        let Some(native) = entry.processes.get_mut(&process.process) else {
            return Ok(());
        };
        let result = stop_process(&entry.sandbox, &entry.id, native).await;
        if result.is_ok() {
            entry.processes.remove(&process.process);
        }
        result
    }

    pub(super) async fn close(&self, resource: &ResourceId) -> Result<()> {
        validate_id(resource)?;
        let slot = {
            let mut state = self.state.lock().await;
            if let Some((kind, _)) = state.reservations.get(resource) {
                if kind != &ReserveRequest::Resource {
                    return Err(failure(
                        tinybox_bus::INVALID_ID,
                        "not a resource reservation",
                    ));
                }
                state.reservations.remove(resource);
            }
            let Some(slot) = state.entries.get(resource).cloned() else {
                return Ok(());
            };
            state
                .reservations
                .retain(|_, (kind, _)| kind != &ReserveRequest::Process(resource.clone()));
            slot
        };
        {
            let mut executions = self
                .executions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            executions.closing.insert(resource.clone());
            if let Some(native) = executions.native.get(resource) {
                native.abort();
            }
        }
        let mut slot = slot.lock().await;
        let mut failure = None;
        if let Some(entry) = slot.as_mut() {
            let sandbox = entry.sandbox.clone();
            let id = entry.id.clone();
            for process in entry.processes.values_mut() {
                if let Err(error) = stop_process(&sandbox, &id, process).await {
                    failure.get_or_insert(error);
                }
            }
            if let Some(collector) = &entry.collector
                && let Err(error) = collector.drain_checked().await
            {
                failure.get_or_insert_with(|| backend_error(&error));
            }
            entry.processes.retain(|_, process| match process {
                OwnedProcess::Native(process) => !process.is_cleaned(),
                OwnedProcess::Sandbox { stopped, .. } => !*stopped,
            });
            if !entry.processes.is_empty() {
                return failure
                    .map_or_else(|| Err(Error::failed("native cleanup remains pending")), Err);
            }
            if entry
                .collector
                .as_ref()
                .is_some_and(|collector| collector.has_pending_cleanup())
            {
                return failure.map_or_else(
                    || Err(Error::failed("collector cleanup remains pending")),
                    Err,
                );
            }
            entry
                .sandbox
                .destroy(&entry.id)
                .await
                .map_err(|error| backend_error(&error))?;
        }
        *slot = None;
        self.state.lock().await.entries.remove(resource);
        let mut executions = self
            .executions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        executions.closing.remove(resource);
        executions.native.remove(resource);
        failure.map_or(Ok(()), Err)
    }

    pub(super) async fn shutdown(&self) -> Result<()> {
        let resources = {
            let mut state = self.state.lock().await;
            state.shutdown = true;
            state.reservations.clear();
            for (_, cancelled) in state.pending_processes.values() {
                cancelled.store(true, Ordering::SeqCst);
            }
            let resources: Vec<_> = state.entries.keys().cloned().collect();
            let mut executions = self
                .executions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            executions.closing.extend(resources.iter().cloned());
            for native in executions.native.values() {
                native.abort();
            }
            resources
        };
        let mut failure = None;
        for resource in resources {
            if let Err(error) = self.close(&resource).await {
                failure.get_or_insert(error);
            }
        }
        loop {
            let finished = self.finished.notified();
            tokio::pin!(finished);
            finished.as_mut().enable();
            if self.state.lock().await.pending_processes.is_empty() {
                break;
            }
            finished.await;
        }
        failure.map_or(Ok(()), Err)
    }
}

fn command(request: ExecRequest) -> tinybox_core::ExecRequest {
    let mut command = tinybox_core::ExecRequest::new(request.argv);
    command.cwd = request.cwd.map(Into::into);
    command.env = request.env;
    command.stdin = request.stdin;
    command
}

async fn stop_process(
    sandbox: &Arc<dyn Sandbox>,
    box_id: &BoxId,
    process: &mut OwnedProcess,
) -> Result<()> {
    match process {
        OwnedProcess::Native(native) => native.stop().await.map_err(|error| backend_error(&error)),
        OwnedProcess::Sandbox { id, stopped } => {
            sandbox
                .stop(box_id, id)
                .await
                .map_err(|error| backend_error(&error))?;
            *stopped = true;
            Ok(())
        }
    }
}

fn failure(name: &str, message: &str) -> Error {
    Error::MethodFailed {
        name: name.into(),
        message: message.into(),
    }
}

fn backend_error(error: &tinybox_core::Error) -> Error {
    let name = if matches!(error, tinybox_core::Error::OutputLimitExceeded { .. }) {
        tinybox_bus::OUTPUT_LIMIT
    } else {
        tinybox_bus::BACKEND_ERROR
    };
    failure(name, &error.to_string())
}

fn validate_id(id: &ResourceId) -> Result<()> {
    if id.0.is_empty()
        || id.0.len() > tinybox_bus::MAX_ID_BYTES
        || !id
            .0
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        Err(failure(
            tinybox_bus::INVALID_ID,
            "invalid reservation identifier",
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
#[path = "resources_tests.rs"]
mod tests;
