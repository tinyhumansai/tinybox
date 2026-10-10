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
    processes: BTreeMap<ResourceId, ProcessId>,
    collector: Option<Arc<tinybox_host::LimitedLocalHost>>,
}

/// Registry owned by one module instance; close and operations are serialized.
pub(super) struct Resources {
    instance: String,
    clock: Arc<dyn Clock>,
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
            let sandbox: Arc<dyn Sandbox> = match request.backend.as_str() {
                "passthrough" => Arc::new(tinybox_core::PassthroughSandbox::new(host, store)),
                "docker" => Arc::new(tinybox_docker::DockerSandbox::new(host, store)),
                "namespace" => Arc::new(tinybox_linux::NamespaceSandbox::new(host, store)),
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
            let info = sandbox
                .create(&spec)
                .await
                .map_err(|error| backend_error(&error))?;
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
            });
            Ok(result)
        }
        .await;
        if allocation.is_err() {
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
        let native = entry
            .sandbox
            .spawn(&entry.id, &command(request.command))
            .await
            .map_err(|error| backend_error(&error))?;
        entry.processes.insert(request.process.clone(), native);
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
        let Some(native) = entry.processes.get(&process.process) else {
            validate_id(&process.process)?;
            return Ok(false);
        };
        let running = entry
            .sandbox
            .is_running(&entry.id, native)
            .await
            .map_err(|error| backend_error(&error))?;
        if !running {
            entry
                .sandbox
                .stop(&entry.id, native)
                .await
                .map_err(|error| backend_error(&error))?;
            entry.processes.remove(&process.process);
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
        let Some(native) = entry.processes.get(&process.process) else {
            return Ok(());
        };
        entry
            .sandbox
            .stop(&entry.id, native)
            .await
            .map_err(|error| backend_error(&error))?;
        entry.processes.remove(&process.process);
        Ok(())
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
        if let Some(entry) = slot.as_ref() {
            if let Some(collector) = &entry.collector {
                collector.drain().await;
            }
            for process in entry.processes.values() {
                entry
                    .sandbox
                    .stop(&entry.id, process)
                    .await
                    .map_err(|error| backend_error(&error))?;
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
        Ok(())
    }
}

fn command(request: ExecRequest) -> tinybox_core::ExecRequest {
    let mut command = tinybox_core::ExecRequest::new(request.argv);
    command.cwd = request.cwd.map(Into::into);
    command.env = request.env;
    command.stdin = request.stdin;
    command
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
