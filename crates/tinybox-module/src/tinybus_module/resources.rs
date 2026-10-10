//! Module-owned sandbox and detached-process lifetimes.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use tinybox_bus::{
    CreateRequest, ExecOutput, ExecRequest, ProcessRef, ResourceId, ResourceInfo, SpawnRequest,
    Workspace,
};
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
}

/// Registry owned by one module instance; close and operations are serialized.
#[derive(Default)]
pub(super) struct Resources {
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    entries: BTreeMap<ResourceId, Resource>,
    issued: BTreeSet<ResourceId>,
}

impl Resources {
    pub(super) async fn create(&self, request: CreateRequest) -> Result<ResourceInfo> {
        self.create_on(request, Arc::new(tinybox_host::LocalHost::new()))
            .await
    }

    async fn create_on(
        &self,
        request: CreateRequest,
        host: Arc<dyn tinybox_core::Host>,
    ) -> Result<ResourceInfo> {
        let mut state = self.state.lock().await;
        reserve(&mut state.issued, &request.resource)?;
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
        let resource = request.resource;
        let result = ResourceInfo {
            resource: resource.clone(),
            backend: request.backend,
            state: info.state.to_string(),
        };
        state.entries.insert(
            resource,
            Resource {
                sandbox,
                id: info.id,
                processes: BTreeMap::new(),
            },
        );
        Ok(result)
    }

    pub(super) async fn inspect(&self, resource: &ResourceId) -> Result<ResourceInfo> {
        let state = self.state.lock().await;
        let entries = &state.entries;
        let entry = entries
            .get(resource)
            .ok_or_else(|| failure(tinybox_bus::UNKNOWN_RESOURCE, "unknown resource"))?;
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
        let state = self.state.lock().await;
        let entries = &state.entries;
        let entry = entries
            .get(&request.resource)
            .ok_or_else(|| failure(tinybox_bus::UNKNOWN_RESOURCE, "unknown resource"))?;
        let output = entry
            .sandbox
            .exec(&entry.id, &command(request))
            .await
            .map_err(|error| backend_error(&error))?;
        Ok(ExecOutput {
            exit_code: output.exit_code,
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }

    pub(super) async fn spawn(&self, request: SpawnRequest) -> Result<ProcessRef> {
        let mut state = self.state.lock().await;
        reserve(&mut state.issued, &request.process)?;
        let entry = state
            .entries
            .get_mut(&request.command.resource)
            .ok_or_else(|| failure(tinybox_bus::UNKNOWN_RESOURCE, "unknown resource"))?;
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
        let state = self.state.lock().await;
        let entries = &state.entries;
        let entry = entries
            .get(&process.resource)
            .ok_or_else(|| failure(tinybox_bus::UNKNOWN_RESOURCE, "unknown resource"))?;
        let native = entry
            .processes
            .get(&process.process)
            .ok_or_else(|| failure(tinybox_bus::UNKNOWN_PROCESS, "unknown process"))?;
        entry
            .sandbox
            .is_running(&entry.id, native)
            .await
            .map_err(|error| backend_error(&error))
    }

    pub(super) async fn cancel(&self, process: &ProcessRef) -> Result<()> {
        let mut state = self.state.lock().await;
        validate_id(&process.process)?;
        state.issued.insert(process.process.clone());
        let Some(entry) = state.entries.get(&process.resource) else {
            return Ok(());
        };
        let Some(native) = entry.processes.get(&process.process) else {
            return Ok(());
        };
        entry
            .sandbox
            .stop(&entry.id, native)
            .await
            .map_err(|error| backend_error(&error))
    }

    pub(super) async fn close(&self, resource: &ResourceId) -> Result<()> {
        let mut state = self.state.lock().await;
        validate_id(resource)?;
        state.issued.insert(resource.clone());
        let Some(entry) = state.entries.get(resource) else {
            return Ok(());
        };
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
        state.entries.remove(resource);
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
    failure(tinybox_bus::BACKEND_ERROR, &error.to_string())
}

fn reserve(issued: &mut BTreeSet<ResourceId>, id: &ResourceId) -> Result<()> {
    validate_id(id)?;
    if !issued.insert(id.clone()) {
        return Err(failure(
            tinybox_bus::DUPLICATE_ID,
            "reservation identifier already used",
        ));
    }
    Ok(())
}

fn validate_id(id: &ResourceId) -> Result<()> {
    if id.0.is_empty() {
        Err(failure(
            tinybox_bus::INVALID_ID,
            "empty reservation identifier",
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
#[path = "resources_tests.rs"]
mod tests;
