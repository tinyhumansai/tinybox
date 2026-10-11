//! Module-owned sandbox and detached-process lifetimes.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tinybox_bus::{
    AbortFileWriteRequest, BeginFileReadRequest, BeginFileWriteRequest, CloseForwardRequest,
    CreateRequest, ExecOutput, ExecRequest, FileChunk, FileReadInfo, FileWriteInfo,
    FileWriteProgress, FinishFileReadRequest, FinishFileWriteRequest, ForwardInfo, ForwardRequest,
    HostConfig, ProcessRef, ReadFileChunkRequest, ReserveRequest, ResourceId, ResourceInfo,
    SpawnRequest, Workspace, WriteFileChunkRequest,
};
use tinybox_core::clock::{Clock, SystemClock};
use tinybox_core::{
    BoxId, BoxSpec, Forward, Host, HostRef, MemoryStore, Placement, ProcessId, Sandbox, SandboxRef,
    WorkspaceSource,
};

use tinybus::{Error, Result};
use tokio::sync::Mutex;

struct Resource {
    host: Arc<dyn Host>,
    native_host: bool,
    sandbox: Arc<dyn Sandbox>,
    id: BoxId,
    execution_supported: bool,
    processes: BTreeMap<ResourceId, OwnedProcess>,
    local_sandbox: Option<Arc<tinybox_core::PassthroughSandbox>>,
    collector: Option<Arc<tinybox_host::LimitedLocalHost>>,
    forwards: BTreeMap<ResourceId, OwnedForward>,
    workspace_root: Option<PathBuf>,
    readers: BTreeMap<ResourceId, OwnedReader>,
    writers: BTreeMap<ResourceId, OwnedWriter>,
    completed_writes: BTreeMap<ResourceId, CompletedWrite>,
    completed_write_order: VecDeque<ResourceId>,
}

struct OwnedReader {
    path: String,
    size: u64,
    reader: Box<dyn tinybox_core::WorkspaceFileReader>,
}

struct OwnedWriter {
    path: String,
    writer: Box<dyn tinybox_core::WorkspaceFileWriter>,
    next_offset: u64,
    last_chunk: Option<(u64, Vec<u8>, u64)>,
}

struct CompletedWrite {
    path: String,
    next_offset: u64,
}

struct OwnedForward {
    guest_port: u16,
    info: ForwardInfo,
    _forward: Forward,
}

struct SandboxSelection {
    sandbox: Arc<dyn Sandbox>,
    local_sandbox: Option<Arc<tinybox_core::PassthroughSandbox>>,
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
        if let ReserveRequest::Process(resource)
        | ReserveRequest::Forward(resource)
        | ReserveRequest::FileRead(resource)
        | ReserveRequest::FileWrite(resource) = &request
            && !state.entries.contains_key(resource)
        {
            return Err(failure(tinybox_bus::UNKNOWN_RESOURCE, "unknown resource"));
        }
        if let ReserveRequest::Process(resource)
        | ReserveRequest::Forward(resource)
        | ReserveRequest::FileRead(resource)
        | ReserveRequest::FileWrite(resource) = &request
            && self
                .executions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .closing
                .contains(resource)
        {
            return Err(failure(tinybox_bus::EXEC_CANCELLED, "resource is closing"));
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
        self.check_reservation(state, id, expected)?;
        state.reservations.remove(id);
        Ok(())
    }

    fn check_reservation(
        &self,
        state: &mut State,
        id: &ResourceId,
        expected: &ReserveRequest,
    ) -> Result<()> {
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
        if expired {
            state.reservations.remove(id);
            return Err(failure(tinybox_bus::DUPLICATE_ID, "reservation expired"));
        }
        Ok(())
    }

    pub(super) async fn create(&self, request: CreateRequest) -> Result<ResourceInfo> {
        let collector = Arc::new(tinybox_host::LimitedLocalHost::new(
            tinybox_bus::MAX_OUTPUT_BYTES,
        ));
        let host = configured_host(&request.host, collector.clone())?;
        self.create_with_platform(request, host, Some(collector), super::Platform::current())
            .await
    }

    #[cfg(test)]
    async fn create_on(
        &self,
        request: CreateRequest,
        host: Arc<dyn tinybox_core::Host>,
    ) -> Result<ResourceInfo> {
        self.create_with_platform(request, host, None, super::Platform::current())
            .await
    }

    #[cfg(test)]
    async fn create_on_for_platform(
        &self,
        request: CreateRequest,
        host: Arc<dyn tinybox_core::Host>,
        platform: super::Platform,
    ) -> Result<ResourceInfo> {
        self.create_with_platform(request, host, None, platform)
            .await
    }

    async fn create_with_platform(
        &self,
        request: CreateRequest,
        host: Arc<dyn tinybox_core::Host>,
        collector: Option<Arc<tinybox_host::LimitedLocalHost>>,
        platform: super::Platform,
    ) -> Result<ResourceInfo> {
        let slot = Arc::new(Mutex::new(None));
        // Own the slot before publishing it. Once it appears in `entries`, a
        // concurrent Close or Shutdown may wait on this guard and observe the
        // allocation created below instead of racing to remove an empty slot.
        let mut slot_guard = Arc::clone(&slot).lock_owned().await;
        {
            let mut state = self.state.lock().await;
            self.consume(&mut state, &request.resource, &ReserveRequest::Resource)?;
            validate_platform_backend(platform, &request.backend)?;
            if state.entries.len() >= tinybox_bus::MAX_ACTIVE_RESOURCES {
                return Err(failure(
                    tinybox_bus::RESOURCE_LIMIT,
                    "active resource limit reached",
                ));
            }
            state.entries.insert(request.resource.clone(), slot.clone());
        }
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
            let resource_host = host.clone();
            let native_host = host.name() == tinybox_host::LOCAL;
            let store = Arc::new(MemoryStore::new());
            let SandboxSelection {
                sandbox,
                local_sandbox,
            } = make_sandbox(&request.backend, host.clone(), store.clone())?;
            let spec = make_spec(&request, host.name())?;
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
                        *slot_guard = Some(Resource {
                            host: resource_host,
                            native_host,
                            sandbox,
                            id: info.id,
                            execution_supported: supports_execution(platform, &request.backend),
                            processes: BTreeMap::new(),
                            collector,
                            local_sandbox,
                            forwards: BTreeMap::new(),
                            workspace_root: directory_workspace(&request.workspace),
                            readers: BTreeMap::new(),
                            writers: BTreeMap::new(),
                            completed_writes: BTreeMap::new(),
                            completed_write_order: VecDeque::new(),
                        });
                    }
                    return Err(backend_error(&error));
                }
            };
            let execution_supported = supports_execution(platform, &request.backend);
            *slot_guard = Some(Resource {
                host: resource_host,
                native_host,
                sandbox: sandbox.clone(),
                id: info.id.clone(),
                execution_supported,
                processes: BTreeMap::new(),
                collector,
                local_sandbox,
                forwards: BTreeMap::new(),
                workspace_root: directory_workspace(&request.workspace),
                readers: BTreeMap::new(),
                writers: BTreeMap::new(),
                completed_writes: BTreeMap::new(),
                completed_write_order: VecDeque::new(),
            });
            let published_ports = published_port_facts(sandbox.as_ref(), &info.id, &info).await?;
            let result = ResourceInfo {
                resource: request.resource.clone(),
                backend: request.backend.clone(),
                state: info.state.to_string(),
                published_ports,
            };
            if self.state.lock().await.shutdown {
                return Err(failure(
                    tinybox_bus::EXEC_CANCELLED,
                    "module shut down during startup",
                ));
            }
            Ok(result)
        }
        .await;
        if allocation.is_err() && slot_guard.is_none() {
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
            published_ports: published_port_facts(entry.sandbox.as_ref(), &entry.id, &info).await?,
        })
    }

    pub(super) async fn begin_file_read(
        &self,
        request: BeginFileReadRequest,
    ) -> Result<FileReadInfo> {
        validate_id(&request.resource)?;
        validate_file_path(&request.path)?;
        validate_id(&request.transfer)?;
        let slot = self.slot(&request.resource).await?;
        let mut slot = slot.lock().await;
        let entry = slot
            .as_mut()
            .ok_or_else(|| failure(tinybox_bus::UNKNOWN_RESOURCE, "closed resource"))?;
        if let Some(existing) = entry.readers.get(&request.transfer) {
            return if existing.path == request.path {
                Ok(FileReadInfo {
                    resource: request.resource,
                    transfer: request.transfer,
                    size: existing.size,
                })
            } else {
                Err(failure(
                    tinybox_bus::INVALID_ID,
                    "file transfer belongs to another path",
                ))
            };
        }
        {
            let mut state = self.state.lock().await;
            let executions = self
                .executions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            check_resource_open(&state, &executions, &request.resource)?;
            self.check_reservation(
                &mut state,
                &request.transfer,
                &ReserveRequest::FileRead(request.resource.clone()),
            )?;
        }
        ensure_transfer_capacity(entry)?;
        let root = workspace_root(entry)?;
        let reader = entry
            .host
            .open_workspace_file(root, Path::new(&request.path))
            .await
            .map_err(|error| file_error(&error))?;
        let size = reader.size();
        {
            let mut state = self.state.lock().await;
            let executions = self
                .executions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            check_resource_open(&state, &executions, &request.resource)?;
            self.consume(
                &mut state,
                &request.transfer,
                &ReserveRequest::FileRead(request.resource.clone()),
            )?;
        }
        entry.readers.insert(
            request.transfer.clone(),
            OwnedReader {
                path: request.path,
                size,
                reader,
            },
        );
        Ok(FileReadInfo {
            resource: request.resource,
            transfer: request.transfer,
            size,
        })
    }

    pub(super) async fn read_file_chunk(&self, request: ReadFileChunkRequest) -> Result<FileChunk> {
        validate_id(&request.resource)?;
        validate_id(&request.transfer)?;
        if request.max_bytes == 0 || request.max_bytes > tinybox_bus::MAX_FILE_CHUNK_BYTES {
            return Err(failure(
                tinybox_bus::INVALID_FILE_CHUNK,
                "invalid read chunk size",
            ));
        }
        let slot = self.slot(&request.resource).await?;
        let mut slot = slot.lock().await;
        let entry = slot
            .as_mut()
            .ok_or_else(|| failure(tinybox_bus::UNKNOWN_RESOURCE, "closed resource"))?;
        check_entry_open(self, &request.resource).await?;
        let reader = entry
            .readers
            .get_mut(&request.transfer)
            .ok_or_else(|| failure(tinybox_bus::UNKNOWN_FILE_TRANSFER, "unknown file reader"))?;
        if request.offset > reader.size {
            return Err(failure(
                tinybox_bus::INVALID_FILE_CHUNK,
                "read offset exceeds file size",
            ));
        }
        let bytes = reader
            .reader
            .read_chunk(request.offset, request.max_bytes)
            .await
            .map_err(|error| file_error(&error))?;
        if bytes.len() > request.max_bytes {
            return Err(failure(
                tinybox_bus::BACKEND_ERROR,
                "workspace reader returned more bytes than requested",
            ));
        }
        Ok(FileChunk {
            offset: request.offset,
            bytes,
            total_bytes: reader.size,
        })
    }

    pub(super) async fn finish_file_read(&self, request: FinishFileReadRequest) -> Result<()> {
        validate_id(&request.resource)?;
        validate_id(&request.transfer)?;
        let slot = self.slot(&request.resource).await?;
        let mut slot = slot.lock().await;
        let entry = slot
            .as_mut()
            .ok_or_else(|| failure(tinybox_bus::UNKNOWN_RESOURCE, "closed resource"))?;
        check_entry_open(self, &request.resource).await?;
        entry
            .readers
            .remove(&request.transfer)
            .ok_or_else(|| failure(tinybox_bus::UNKNOWN_FILE_TRANSFER, "unknown file reader"))?;
        Ok(())
    }

    pub(super) async fn begin_file_write(
        &self,
        request: BeginFileWriteRequest,
    ) -> Result<FileWriteInfo> {
        validate_id(&request.resource)?;
        validate_file_path(&request.path)?;
        validate_id(&request.transfer)?;
        let slot = self.slot(&request.resource).await?;
        let mut slot = slot.lock().await;
        let entry = slot
            .as_mut()
            .ok_or_else(|| failure(tinybox_bus::UNKNOWN_RESOURCE, "closed resource"))?;
        if let Some(completed) = entry.completed_writes.get(&request.transfer) {
            return if completed.path == request.path {
                Ok(FileWriteInfo {
                    resource: request.resource,
                    transfer: request.transfer,
                    next_offset: completed.next_offset,
                })
            } else {
                Err(failure(
                    tinybox_bus::INVALID_ID,
                    "file transfer belongs to another path",
                ))
            };
        }
        if let Some(existing) = entry.writers.get(&request.transfer) {
            return if existing.path == request.path {
                Ok(FileWriteInfo {
                    resource: request.resource,
                    transfer: request.transfer,
                    next_offset: existing.next_offset,
                })
            } else {
                Err(failure(
                    tinybox_bus::INVALID_ID,
                    "file transfer belongs to another path",
                ))
            };
        }
        {
            let mut state = self.state.lock().await;
            let executions = self
                .executions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            check_resource_open(&state, &executions, &request.resource)?;
            self.check_reservation(
                &mut state,
                &request.transfer,
                &ReserveRequest::FileWrite(request.resource.clone()),
            )?;
        }
        ensure_transfer_capacity(entry)?;
        let root = workspace_root(entry)?;
        let writer = entry
            .host
            .begin_workspace_file_write(root, Path::new(&request.path), &request.transfer.0)
            .await
            .map_err(|error| file_error(&error))?;
        let admission = {
            let mut state = self.state.lock().await;
            let executions = self
                .executions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            check_resource_open(&state, &executions, &request.resource).and_then(|()| {
                self.consume(
                    &mut state,
                    &request.transfer,
                    &ReserveRequest::FileWrite(request.resource.clone()),
                )
            })
        };
        if let Err(error) = admission {
            let mut writer = writer;
            let _ = writer.abort().await;
            return Err(error);
        }
        entry.writers.insert(
            request.transfer.clone(),
            OwnedWriter {
                path: request.path,
                writer,
                next_offset: 0,
                last_chunk: None,
            },
        );
        Ok(FileWriteInfo {
            resource: request.resource,
            transfer: request.transfer,
            next_offset: 0,
        })
    }

    pub(super) async fn write_file_chunk(
        &self,
        request: WriteFileChunkRequest,
    ) -> Result<FileWriteProgress> {
        validate_id(&request.resource)?;
        validate_id(&request.transfer)?;
        if request.bytes.is_empty() || request.bytes.len() > tinybox_bus::MAX_FILE_CHUNK_BYTES {
            return Err(failure(
                tinybox_bus::INVALID_FILE_CHUNK,
                "invalid write chunk size",
            ));
        }
        let slot = self.slot(&request.resource).await?;
        let mut slot = slot.lock().await;
        let entry = slot
            .as_mut()
            .ok_or_else(|| failure(tinybox_bus::UNKNOWN_RESOURCE, "closed resource"))?;
        check_entry_open(self, &request.resource).await?;
        let writer = entry
            .writers
            .get_mut(&request.transfer)
            .ok_or_else(|| failure(tinybox_bus::UNKNOWN_FILE_TRANSFER, "unknown file writer"))?;
        if let Some((offset, bytes, next)) = &writer.last_chunk
            && *offset == request.offset
        {
            return if bytes == &request.bytes {
                Ok(FileWriteProgress { next_offset: *next })
            } else {
                Err(failure(
                    tinybox_bus::INVALID_FILE_CHUNK,
                    "conflicting retry at an acknowledged offset",
                ))
            };
        }
        if request.offset != writer.next_offset {
            return Err(failure(
                tinybox_bus::INVALID_FILE_CHUNK,
                "write offset is not the next expected offset",
            ));
        }
        let next = request
            .offset
            .checked_add(request.bytes.len() as u64)
            .filter(|next| *next <= tinybox_bus::MAX_FILE_BYTES)
            .ok_or_else(|| failure(tinybox_bus::FILE_LIMIT, "workspace file size limit reached"))?;
        let acknowledged = writer
            .writer
            .write_chunk(request.offset, &request.bytes)
            .await
            .map_err(|error| file_error(&error))?;
        if acknowledged != next {
            return Err(failure(
                tinybox_bus::BACKEND_ERROR,
                "workspace writer returned an invalid offset",
            ));
        }
        writer.last_chunk = Some((request.offset, request.bytes, next));
        writer.next_offset = next;
        Ok(FileWriteProgress { next_offset: next })
    }

    pub(super) async fn finish_file_write(
        &self,
        request: FinishFileWriteRequest,
    ) -> Result<FileWriteProgress> {
        validate_id(&request.resource)?;
        validate_id(&request.transfer)?;
        let slot = self.slot(&request.resource).await?;
        let mut slot = slot.lock().await;
        let entry = slot
            .as_mut()
            .ok_or_else(|| failure(tinybox_bus::UNKNOWN_RESOURCE, "closed resource"))?;
        check_entry_open(self, &request.resource).await?;
        if let Some(completed) = entry.completed_writes.get(&request.transfer) {
            return Ok(FileWriteProgress {
                next_offset: completed.next_offset,
            });
        }
        let writer = entry
            .writers
            .get_mut(&request.transfer)
            .ok_or_else(|| failure(tinybox_bus::UNKNOWN_FILE_TRANSFER, "unknown file writer"))?;
        let next_offset = writer
            .writer
            .finish()
            .await
            .map_err(|error| file_error(&error))?;
        let completed = CompletedWrite {
            path: writer.path.clone(),
            next_offset,
        };
        entry.writers.remove(&request.transfer);
        entry
            .completed_writes
            .insert(request.transfer.clone(), completed);
        entry.completed_write_order.push_back(request.transfer);
        while entry.completed_write_order.len() > tinybox_bus::MAX_FILE_TRANSFERS_PER_RESOURCE {
            if let Some(expired) = entry.completed_write_order.pop_front() {
                entry.completed_writes.remove(&expired);
            }
        }
        Ok(FileWriteProgress { next_offset })
    }

    pub(super) async fn abort_file_write(&self, request: AbortFileWriteRequest) -> Result<()> {
        validate_id(&request.resource)?;
        validate_id(&request.transfer)?;
        let slot = self.slot(&request.resource).await?;
        let mut slot = slot.lock().await;
        let entry = slot
            .as_mut()
            .ok_or_else(|| failure(tinybox_bus::UNKNOWN_RESOURCE, "closed resource"))?;
        check_entry_open(self, &request.resource).await?;
        let writer = entry
            .writers
            .get_mut(&request.transfer)
            .ok_or_else(|| failure(tinybox_bus::UNKNOWN_FILE_TRANSFER, "unknown file writer"))?;
        writer
            .writer
            .abort()
            .await
            .map_err(|error| file_error(&error))?;
        entry.writers.remove(&request.transfer);
        Ok(())
    }

    pub(super) async fn forward(&self, request: ForwardRequest) -> Result<ForwardInfo> {
        validate_id(&request.forward)?;
        let slot = self.slot(&request.resource).await?;
        let mut slot = slot.lock().await;
        let entry = slot
            .as_mut()
            .ok_or_else(|| failure(tinybox_bus::UNKNOWN_RESOURCE, "closed resource"))?;
        {
            let mut state = self.state.lock().await;
            let executions = self
                .executions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            check_resource_open(&state, &executions, &request.resource)?;
            if let Some(existing) = entry.forwards.get(&request.forward) {
                return if existing.guest_port == request.guest_port {
                    Ok(existing.info.clone())
                } else {
                    Err(failure(
                        tinybox_bus::INVALID_ID,
                        "forward handle belongs to another guest port",
                    ))
                };
            }
            self.check_reservation(
                &mut state,
                &request.forward,
                &ReserveRequest::Forward(request.resource.clone()),
            )?;
        }
        if entry.forwards.len() >= tinybox_bus::MAX_FORWARDS_PER_RESOURCE {
            return Err(failure(
                tinybox_bus::RESOURCE_LIMIT,
                "forward limit reached",
            ));
        }
        self.open_forward(entry, &request).await
    }

    async fn open_forward(
        &self,
        entry: &mut Resource,
        request: &ForwardRequest,
    ) -> Result<ForwardInfo> {
        let published = entry
            .sandbox
            .published_ports(&entry.id)
            .await
            .map_err(|error| backend_error(&error))?
            .into_iter()
            .find(|port| port.guest == request.guest_port && port.host.is_some())
            .ok_or_else(|| {
                failure(
                    tinybox_bus::UNSUPPORTED_OPERATION,
                    "guest port is not published on this resource",
                )
            })?;
        let Some(port) = published.host else {
            return Err(failure(
                tinybox_bus::UNSUPPORTED_OPERATION,
                "published host port is unavailable",
            ));
        };
        let remote = std::net::SocketAddr::from(([127, 0, 0, 1], port));
        {
            let mut state = self.state.lock().await;
            let executions = self
                .executions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            check_resource_open(&state, &executions, &request.resource)?;
            self.check_reservation(
                &mut state,
                &request.forward,
                &ReserveRequest::Forward(request.resource.clone()),
            )?;
        }
        let forward = entry
            .host
            .forward(remote)
            .await
            .map_err(|error| backend_error(&error))?;
        let info = ForwardInfo {
            resource: request.resource.clone(),
            forward: request.forward.clone(),
            local_address: forward.local_addr().to_string(),
        };
        {
            let mut state = self.state.lock().await;
            let executions = self
                .executions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            check_resource_open(&state, &executions, &request.resource)?;
            self.consume(
                &mut state,
                &request.forward,
                &ReserveRequest::Forward(request.resource.clone()),
            )?;
            // Publish while holding the same state -> executions admission
            // barrier used by Close and Shutdown. If either has marked this
            // resource, the local `forward` drops here and closes the tunnel.
            entry.forwards.insert(
                request.forward.clone(),
                OwnedForward {
                    guest_port: request.guest_port,
                    info: info.clone(),
                    _forward: forward,
                },
            );
        }
        Ok(info)
    }

    pub(super) async fn close_forward(&self, request: CloseForwardRequest) -> Result<()> {
        validate_id(&request.resource)?;
        validate_id(&request.forward)?;
        let slot = {
            let mut state = self.state.lock().await;
            if let Some((kind, _)) = state.reservations.get(&request.forward) {
                if kind != &ReserveRequest::Forward(request.resource.clone()) {
                    return Err(failure(
                        tinybox_bus::INVALID_ID,
                        "forward reservation belongs to another resource",
                    ));
                }
                state.reservations.remove(&request.forward);
            }
            state.entries.get(&request.resource).cloned()
        };
        let Some(slot) = slot else {
            return Ok(());
        };
        let mut slot = slot.lock().await;
        if let Some(entry) = slot.as_mut() {
            entry.forwards.remove(&request.forward);
        }
        Ok(())
    }

    pub(super) async fn exec(&self, request: ExecRequest) -> Result<ExecOutput> {
        let slot = self.slot(&request.resource).await?;
        let slot = slot.lock().await;
        let entry = slot
            .as_ref()
            .ok_or_else(|| failure(tinybox_bus::UNKNOWN_RESOURCE, "closed resource"))?;
        let resource = request.resource.clone();
        if !entry.execution_supported {
            return Err(failure(
                tinybox_bus::UNSUPPORTED_OPERATION,
                "module Exec is not supported for this backend on this platform",
            ));
        }
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

    fn ensure_not_closing(&self, resource: &ResourceId) -> Result<()> {
        if self
            .executions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .closing
            .contains(resource)
        {
            return Err(failure(tinybox_bus::EXEC_CANCELLED, "resource is closing"));
        }
        Ok(())
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
        self.ensure_not_closing(&request.command.resource)?;
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
        if !entry.execution_supported {
            return Err(failure(
                tinybox_bus::UNSUPPORTED_OPERATION,
                "module Spawn is not supported for this backend on this platform",
            ));
        }
        let resource = request.command.resource.clone();
        if let Some(local) = entry.local_sandbox.as_ref()
            && entry.native_host
        {
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
        } else if entry.host.name() == tinybox_ssh::NAME {
            spawn_remote_process(entry, &request).await?;
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
            state.reservations.retain(|_, (kind, _)| {
                kind != &ReserveRequest::Process(resource.clone())
                    && kind != &ReserveRequest::Forward(resource.clone())
                    && kind != &ReserveRequest::FileRead(resource.clone())
                    && kind != &ReserveRequest::FileWrite(resource.clone())
            });
            let mut executions = self
                .executions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            executions.closing.insert(resource.clone());
            if let Some(native) = executions.native.get(resource) {
                native.abort();
            }
            slot
        };
        let mut slot = slot.lock().await;
        let mut failure = None;
        if let Some(entry) = slot.as_mut() {
            // Stop tunnel admission before touching the sandbox. Even when a
            // process or container cleanup must be retried, the closed
            // resource no longer accepts new forwarded connections.
            entry.forwards.clear();
            abort_writers(entry, &mut failure).await?;
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

async fn abort_writers(entry: &mut Resource, failure: &mut Option<Error>) -> Result<()> {
    let writer_ids: Vec<_> = entry.writers.keys().cloned().collect();
    for transfer in writer_ids {
        let result = match entry.writers.get_mut(&transfer) {
            Some(writer) => writer
                .writer
                .abort()
                .await
                .map_err(|error| file_error(&error)),
            None => Ok(()),
        };
        match result {
            Ok(()) => {
                entry.writers.remove(&transfer);
            }
            Err(error) => {
                failure.get_or_insert(error);
            }
        }
    }
    if entry.writers.is_empty() {
        Ok(())
    } else {
        failure.take().map_or_else(
            || Err(Error::failed("staged file cleanup remains pending")),
            Err,
        )
    }
}

fn directory_workspace(workspace: &Workspace) -> Option<PathBuf> {
    match workspace {
        Workspace::Directory(path) => Some(PathBuf::from(path)),
        Workspace::Image(_) => None,
    }
}

fn workspace_root(entry: &Resource) -> Result<&Path> {
    entry.workspace_root.as_deref().ok_or_else(|| {
        failure(
            tinybox_bus::FILE_UNSUPPORTED,
            "workspace file transfer is unavailable for image workspaces",
        )
    })
}

fn validate_file_path(path: &str) -> Result<()> {
    if path.is_empty()
        || path.len() > tinybox_bus::MAX_FILE_PATH_BYTES
        || path.contains('\0')
        || path.contains('\\')
        || path.contains(':')
        || Path::new(path)
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(failure(
            tinybox_bus::INVALID_FILE_PATH,
            "workspace file path must be normalized and relative",
        ));
    }
    Ok(())
}

fn ensure_transfer_capacity(entry: &Resource) -> Result<()> {
    if entry.readers.len() + entry.writers.len() >= tinybox_bus::MAX_FILE_TRANSFERS_PER_RESOURCE {
        return Err(failure(
            tinybox_bus::FILE_LIMIT,
            "workspace file transfer limit reached",
        ));
    }
    Ok(())
}

async fn check_entry_open(resources: &Resources, resource: &ResourceId) -> Result<()> {
    let state = resources.state.lock().await;
    let executions = resources
        .executions
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    check_resource_open(&state, &executions, resource)
}

fn file_error(error: &tinybox_core::Error) -> Error {
    let name = match error {
        tinybox_core::Error::Unsupported { .. }
        | tinybox_core::Error::UnsupportedHostFileTransfer { .. }
        | tinybox_core::Error::UnsupportedWorkspaceSource { .. } => tinybox_bus::FILE_UNSUPPORTED,
        tinybox_core::Error::InvalidWorkspacePath => tinybox_bus::INVALID_FILE_PATH,
        tinybox_core::Error::InvalidFileTransfer { .. } => tinybox_bus::INVALID_FILE_CHUNK,
        _ => tinybox_bus::FILE_ERROR,
    };
    failure(name, "workspace file operation failed")
}

fn check_resource_open(
    state: &State,
    executions: &Executions,
    resource: &ResourceId,
) -> Result<()> {
    if state.shutdown {
        return Err(failure(tinybox_bus::EXEC_CANCELLED, "module is shut down"));
    }
    if executions.closing.contains(resource) {
        return Err(failure(tinybox_bus::EXEC_CANCELLED, "resource is closing"));
    }
    Ok(())
}

fn make_sandbox(
    backend: &str,
    host: Arc<dyn Host>,
    store: Arc<MemoryStore>,
) -> Result<SandboxSelection> {
    match backend {
        "passthrough" => {
            let sandbox = Arc::new(tinybox_core::PassthroughSandbox::new(host, store));
            Ok(SandboxSelection {
                sandbox: sandbox.clone(),
                local_sandbox: Some(sandbox),
            })
        }
        "docker" => Ok(SandboxSelection {
            sandbox: Arc::new(tinybox_docker::DockerSandbox::new(host, store)),
            local_sandbox: None,
        }),
        "namespace" => Ok(SandboxSelection {
            sandbox: Arc::new(tinybox_linux::NamespaceSandbox::new(host, store)),
            local_sandbox: None,
        }),
        _ => Err(failure(
            tinybox_bus::UNSUPPORTED_BACKEND,
            "unsupported sandbox backend",
        )),
    }
}

async fn published_port_facts(
    sandbox: &dyn Sandbox,
    id: &BoxId,
    info: &tinybox_core::BoxInfo,
) -> Result<Vec<tinybox_bus::PublishedPort>> {
    if info.spec.ports.is_empty() {
        return Ok(Vec::new());
    }
    Ok(sandbox
        .published_ports(id)
        .await
        .map_err(|error| backend_error(&error))?
        .into_iter()
        .filter_map(|port| {
            port.host.map(|host| tinybox_bus::PublishedPort {
                guest: port.guest,
                host,
            })
        })
        .collect())
}

fn make_spec(request: &CreateRequest, host: &str) -> Result<BoxSpec> {
    let source = match &request.workspace {
        Workspace::Directory(path) => WorkspaceSource::LocalDir(path.into()),
        Workspace::Image(image) => WorkspaceSource::OciImage(image.clone()),
    };
    let placement = Placement::new(
        HostRef::new(host).map_err(|error| backend_error(&error))?,
        SandboxRef::new(&request.backend).map_err(|error| backend_error(&error))?,
    );
    let mut spec = BoxSpec::new(placement, source);
    spec.env = request.env.clone();
    spec.network = match request.network {
        tinybox_bus::NetworkPolicy::Denied => tinybox_core::NetworkPolicy::Denied,
        tinybox_bus::NetworkPolicy::Egress => tinybox_core::NetworkPolicy::Egress,
        tinybox_bus::NetworkPolicy::Open => tinybox_core::NetworkPolicy::Open,
    };
    spec.resources = tinybox_core::Resources {
        cpu_millis: request.resources.cpu_millis,
        memory_bytes: request.resources.memory_bytes,
        pids_max: request.resources.pids_max,
        disk_bytes: request.resources.disk_bytes,
    };
    spec.ports
        .extend(request.ports.iter().map(|port| tinybox_core::PortMapping {
            guest: port.guest,
            host: port.host,
        }));
    Ok(spec)
}

async fn spawn_remote_process(entry: &mut Resource, request: &SpawnRequest) -> Result<()> {
    let process_id = entry
        .sandbox
        .spawn(&entry.id, &command(request.command.clone()))
        .await
        .map_err(|error| backend_error(&error))?;
    entry.processes.insert(
        request.process.clone(),
        OwnedProcess::Sandbox {
            id: process_id,
            stopped: false,
        },
    );
    Ok(())
}

fn command(request: ExecRequest) -> tinybox_core::ExecRequest {
    let mut command = tinybox_core::ExecRequest::new(request.argv);
    command.cwd = request.cwd.map(Into::into);
    command.env = request.env;
    command.stdin = request.stdin;
    command
}

fn validate_platform_backend(platform: super::Platform, backend: &str) -> Result<()> {
    if super::supports_create_backend(platform, backend) {
        Ok(())
    } else {
        Err(failure(
            tinybox_bus::UNSUPPORTED_BACKEND,
            "sandbox backend is unavailable on this platform",
        ))
    }
}

pub(super) fn supports_execution(platform: super::Platform, backend: &str) -> bool {
    matches!(
        platform,
        super::Platform::Linux | super::Platform::Unix | super::Platform::Windows
    ) && matches!(backend, "passthrough" | "docker")
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

fn configured_host(config: &HostConfig, local: Arc<dyn Host>) -> Result<Arc<dyn Host>> {
    match config {
        HostConfig::Local => Ok(local),
        HostConfig::Ssh(config) => {
            let mut target = tinybox_ssh::SshTarget::new(config.destination.clone())
                .map_err(|error| backend_error(&error))?;
            if let Some(port) = config.port {
                target = target.with_port(port);
            }
            if let Some(identity) = &config.identity {
                target = target.with_identity(identity);
            }
            if let Some(known_hosts) = &config.known_hosts {
                target = target.with_known_hosts(known_hosts);
            }
            if config.accept_new_host_key {
                target = target.accepting_new_host_key();
            }
            Ok(Arc::new(tinybox_ssh::SshHost::new(local, target)))
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
