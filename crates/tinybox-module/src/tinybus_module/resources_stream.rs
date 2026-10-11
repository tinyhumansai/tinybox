//! Owned live executions; native lifecycle stays with the resource collector.
use super::{
    Arc, Error, Host, Mutex, ProcessRef, ReserveRequest, ResourceId, Resources, Result,
    SpawnRequest, backend_error, check_resource_open, command, failure, validate_id,
};
use crate::tinybus_module::output::OutputJournal;
use tinybox_bus::{ExecutionFailure, OutputBatch};

const MAX_STREAM_EXECUTIONS: usize = 32;

pub(super) struct StreamExecution {
    request: SpawnRequest,
    journal: Arc<OutputJournal>,
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    collector: Arc<tinybox_host::LimitedLocalHost>,
}
impl StreamExecution {
    fn start(
        request: SpawnRequest,
        resolved: tinybox_core::ExecRequest,
        collector: Arc<tinybox_host::LimitedLocalHost>,
    ) -> Self {
        let journal = Arc::new(OutputJournal::default());
        let observer = journal.clone();
        let runner = collector.clone();
        let task = tokio::spawn(async move {
            let _completion = CompletionGuard(observer.clone());
            let result = runner.run_observed(&resolved, observer.clone()).await;
            if runner.has_pending_cleanup() {
                observer.finish_failed(ExecutionFailure::CleanupFailed);
            } else if observer.cancel_requested() {
                observer.finish_exit(0);
            } else {
                match result {
                    Ok(output) => observer.finish_exit(output.exit_code),
                    Err(tinybox_core::Error::OutputLimitExceeded { .. }) => {
                        observer.finish_failed(ExecutionFailure::OutputLimit);
                    }
                    Err(_) => observer.finish_failed(ExecutionFailure::BackendFailed),
                }
            }
        });
        Self {
            request,
            journal,
            task: Mutex::new(Some(task)),
            collector,
        }
    }
    pub(super) fn running(&self) -> bool {
        !self.journal.cleanup_acknowledged()
    }
    pub(super) fn cleanup_acknowledged(&self) -> bool {
        self.journal.cleanup_acknowledged()
    }
    pub(super) async fn stop(&self) -> Result<()> {
        self.journal.cancel();
        let mut task = self.task.lock().await;
        if let Some(join) = task.as_mut() {
            if join.await.is_err() {
                self.journal.finish_failed(ExecutionFailure::CleanupFailed);
            }
            task.take();
        }
        self.collector.drain_checked().await.map_err(|_| {
            failure(
                tinybox_bus::BACKEND_ERROR,
                "native stream cleanup remains pending",
            )
        })?;
        if !self.journal.cleanup_acknowledged() {
            self.journal.finish_failed(ExecutionFailure::BackendFailed);
        }
        Ok(())
    }
}
impl Drop for StreamExecution {
    fn drop(&mut self) {
        self.journal.cancel();
    }
}
struct CompletionGuard(Arc<OutputJournal>);
impl Drop for CompletionGuard {
    fn drop(&mut self) {
        self.0.finish_failed(ExecutionFailure::CleanupFailed);
    }
}

impl Resources {
    pub(in crate::tinybus_module) async fn start_exec(
        &self,
        request: SpawnRequest,
    ) -> Result<ProcessRef> {
        validate_id(&request.process)?;
        validate_id(&request.command.resource)?;
        let process = ProcessRef {
            resource: request.command.resource.clone(),
            process: request.process.clone(),
        };
        if let Some(existing) = self.stream(&process)? {
            return if existing.request == request {
                Ok(process)
            } else {
                Err(failure(
                    tinybox_bus::INVALID_ID,
                    "stream identifier belongs to another command",
                ))
            };
        }
        let slot = self.slot(&process.resource).await?;
        let slot = slot.lock().await;
        let entry = slot
            .as_ref()
            .ok_or_else(|| failure(tinybox_bus::UNKNOWN_RESOURCE, "closed resource"))?;
        if !entry.execution_supported || !entry.native_host || entry.local_sandbox.is_none() {
            return Err(failure(
                tinybox_bus::UNSUPPORTED_OPERATION,
                "live output is unavailable for this provider",
            ));
        }
        if entry.collector.is_none() {
            return Err(failure(
                tinybox_bus::UNSUPPORTED_OPERATION,
                "owned native collector unavailable",
            ));
        }
        // Each execution owns its cleanup collector. Cancelling one stream must
        // not drain an unrelated running supervisor or inherit its failure.
        let collector = Arc::new(tinybox_host::LimitedLocalHost::new(
            tinybox_bus::MAX_OUTPUT_BYTES,
        ));
        // Resolve before consuming admission, and fence native start against Close.
        let resolved = entry
            .local_sandbox
            .as_ref()
            .ok_or_else(|| {
                failure(
                    tinybox_bus::UNSUPPORTED_OPERATION,
                    "local sandbox unavailable",
                )
            })?
            .resolve_command(&entry.id, &command(request.command.clone()))
            .map_err(|error| backend_error(&error))?;
        let mut state = self.state.lock().await;
        let executions = self
            .executions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        check_resource_open(&state, &executions, &process.resource)?;
        let mut streams = self
            .streams
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(existing) = streams.get(&process.process) {
            return if existing.request == request {
                Ok(process)
            } else {
                Err(failure(
                    tinybox_bus::INVALID_ID,
                    "stream identifier belongs to another command",
                ))
            };
        }
        if entry.processes.len()
            + streams
                .values()
                .filter(|stream| stream.request.command.resource == process.resource)
                .count()
            >= tinybox_bus::MAX_PROCESSES_PER_RESOURCE
        {
            return Err(failure(
                tinybox_bus::RESOURCE_LIMIT,
                "resource process limit reached",
            ));
        }
        if streams.len() >= MAX_STREAM_EXECUTIONS {
            return Err(failure(
                tinybox_bus::RESOURCE_LIMIT,
                "live execution admission limit reached",
            ));
        }
        self.consume(
            &mut state,
            &request.process,
            &ReserveRequest::Process(process.resource.clone()),
        )?;
        streams.insert(
            process.process.clone(),
            Arc::new(StreamExecution::start(request, resolved, collector)),
        );
        Ok(process)
    }

    pub(super) fn stream(&self, process: &ProcessRef) -> Result<Option<Arc<StreamExecution>>> {
        validate_id(&process.resource)?;
        validate_id(&process.process)?;
        let streams = self
            .streams
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let found = streams.get(&process.process).cloned();
        if found
            .as_ref()
            .is_some_and(|stream| stream.request.command.resource != process.resource)
        {
            return Err(failure(
                tinybox_bus::INVALID_ID,
                "stream belongs to another resource",
            ));
        }
        Ok(found)
    }
    pub(super) fn streams_for(&self, resource: &ResourceId) -> Vec<Arc<StreamExecution>> {
        self.streams
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .filter(|stream| stream.request.command.resource == *resource)
            .cloned()
            .collect()
    }
    pub(super) fn at_process_limit(&self, entry: &super::Resource, resource: &ResourceId) -> bool {
        entry.processes.len() + self.streams_for(resource).len()
            >= tinybox_bus::MAX_PROCESSES_PER_RESOURCE
    }
    pub(super) fn stream_cleanup_pending(&self, resource: &ResourceId) -> bool {
        self.streams_for(resource)
            .iter()
            .any(|stream| !stream.cleanup_acknowledged())
    }
    pub(super) async fn close_streams(&self, resource: &ResourceId) -> Result<()> {
        let mut failure = None;
        for stream in self.streams_for(resource) {
            if let Err(error) = stream.stop().await {
                failure.get_or_insert(error);
            }
        }
        if self.stream_cleanup_pending(resource) {
            return Err(failure.unwrap_or_else(|| Error::failed("stream cleanup remains pending")));
        }
        self.retire_streams(resource);
        failure.map_or(Ok(()), Err)
    }
    pub(super) fn retire_streams(&self, resource: &ResourceId) {
        self.streams
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|_, stream| stream.request.command.resource != *resource);
    }
    pub(in crate::tinybus_module) async fn read_output(
        &self,
        process: &ProcessRef,
        cursor: u64,
    ) -> Result<OutputBatch> {
        let result = self
            .stream(process)?
            .ok_or_else(|| failure(tinybox_bus::UNKNOWN_PROCESS, "unknown execution journal"))?
            .journal
            .read(cursor)
            .map_err(|_| failure(tinybox_bus::INVALID_ID, "invalid output cursor"));
        std::future::ready(result).await
    }
    pub(in crate::tinybus_module) async fn release_output(
        &self,
        process: &ProcessRef,
    ) -> Result<()> {
        if let Some(stream) = self.stream(process)? {
            if !stream.cleanup_acknowledged() {
                return Err(failure(
                    tinybox_bus::UNSUPPORTED_OPERATION,
                    "execution cleanup is not acknowledged",
                ));
            }
            stream.stop().await?;
            self.streams
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&process.process);
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "resources_stream_tests.rs"]
mod tests;
