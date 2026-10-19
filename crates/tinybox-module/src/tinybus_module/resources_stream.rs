//! Owned live executions; native lifecycle stays with the resource collector.
use super::{
    Arc, Error, Host, Mutex, ProcessRef, ReserveRequest, ResourceId, Resources, Result,
    SpawnRequest, backend_error, check_resource_open, command, failure, validate_id,
};
use crate::tinybus_module::output::OutputJournal;
use tinybox_bus::{ExecutionFailure, OutputBatch};

pub(super) const MAX_STREAM_EXECUTIONS: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
enum NativeJailRequest {
    Legacy(tinybox_bus::NativeJailConfig),
    Resources(tinybox_bus::NativeJailRequest),
}

pub(super) struct StreamExecution {
    request: SpawnRequest,
    shell: Option<tinybox_bus::ShellExecRequest>,
    platform_shell: Option<tinybox_bus::SelectShellRequest>,
    jail: Option<NativeJailRequest>,
    journal: Arc<OutputJournal>,
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    collector: Collector,
    timed_out: Arc<std::sync::atomic::AtomicBool>,
}
#[derive(Clone)]
enum Collector {
    Shell(Arc<super::super::native_shell::ShellContext>),
    PlatformShell(
        Arc<tinybox_host::LimitedLocalHost>,
        tinybox_bus::SelectShellRequest,
    ),
    Host(
        Arc<dyn tinybox_core::Host>,
        Option<Arc<tinybox_host::LimitedLocalHost>>,
    ),
    Jailed(Arc<tinybox_host::JailLocalHost>),
    Sandbox(
        Arc<dyn tinybox_core::Sandbox>,
        tinybox_core::BoxId,
        Option<Arc<tinybox_host::LimitedLocalHost>>,
    ),
}
enum CollectorPreparation {
    Ready(Collector),
    Shell(
        Box<(
            tinybox_bus::ShellExecRequest,
            std::path::PathBuf,
            tinybox_core::ExecRequest,
        )>,
    ),
}
impl CollectorPreparation {
    async fn finish(self) -> Result<Collector> {
        match self {
            Self::Ready(collector) => Ok(collector),
            Self::Shell(preparation) => {
                let (request, root, resolved) = *preparation;
                Ok(Collector::Shell(
                    super::super::native_shell::ShellContext::prepare_owned(
                        request, root, resolved,
                    )
                    .await?,
                ))
            }
        }
    }
}
impl Collector {
    async fn run(
        &self,
        command: &tinybox_core::ExecRequest,
        observer: Arc<OutputJournal>,
    ) -> tinybox_core::Result<tinybox_core::ExecOutput> {
        match self {
            Self::Shell(shell) => shell.run(command, observer).await,
            Self::PlatformShell(host, shell) => {
                host.run_shell_observed(command, shell, observer).await
            }
            Self::Host(host, _) => host.run_observed(command, observer).await,
            Self::Jailed(host) => host.run_observed(command, observer).await,
            Self::Sandbox(sandbox, id, _) => sandbox.exec_observed(id, command, observer).await,
        }
    }
    fn pending(&self) -> bool {
        match self {
            Self::Shell(shell) => shell.pending(),
            Self::PlatformShell(host, _) => host.has_pending_cleanup(),
            Self::Host(host, native) => {
                host.has_pending_observed_cleanup()
                    || native
                        .as_ref()
                        .is_some_and(|native| native.has_pending_cleanup())
            }
            Self::Jailed(host) => host.has_pending_cleanup(),
            Self::Sandbox(sandbox, _, native) => {
                sandbox.has_pending_observed_cleanup()
                    || native
                        .as_ref()
                        .is_some_and(|native| native.has_pending_cleanup())
            }
        }
    }
    fn acknowledge_destroyed_box(&self, id: &tinybox_core::BoxId) {
        if let Self::Sandbox(sandbox, owned_id, _) = self
            && owned_id == id
        {
            sandbox.acknowledge_observed_cleanup_for_destroyed_box(id);
        }
    }
    async fn drain(&self) -> tinybox_core::Result<()> {
        match self {
            Self::Shell(shell) => shell.drain().await,
            Self::PlatformShell(host, _) => host.drain_checked().await,
            Self::Host(host, native) => {
                let remote = host.retry_observed_cleanup().await;
                if let Some(native) = native {
                    native.drain_checked().await?;
                }
                remote
            }
            Self::Jailed(host) => host.drain_checked().await,
            Self::Sandbox(sandbox, _, native) => {
                let remote = sandbox.retry_observed_cleanup().await;
                if let Some(native) = native {
                    native.drain_checked().await?;
                }
                remote
            }
        }
    }
}
fn select_collector(
    entry: &super::Resource,
    jail: Option<&NativeJailRequest>,
    resolved: &mut tinybox_core::ExecRequest,
) -> Result<Collector> {
    Ok(if let Some(config) = jail {
        if !entry.native_host || entry.local_sandbox.is_none() {
            return Err(failure(
                tinybox_bus::UNSUPPORTED_OPERATION,
                "native jail requires local passthrough execution",
            ));
        }
        let root = entry.workspace_root.as_ref().ok_or_else(|| {
            failure(
                tinybox_bus::UNSUPPORTED_OPERATION,
                "native jail requires a directory resource",
            )
        })?;
        Collector::Jailed(match config {
            NativeJailRequest::Legacy(config) => super::super::native_jail::collector(
                root,
                config,
                resolved,
                tinybox_jail::default_backend(),
            )?,
            NativeJailRequest::Resources(config) => {
                super::super::native_jail::collector_with_resources(root, config, resolved)?
            }
        })
    } else {
        let native = Arc::new(tinybox_host::LimitedLocalHost::new(
            tinybox_bus::MAX_OUTPUT_BYTES,
        ));
        let host = super::configured_host(&entry.host_config, native.clone())?;
        if let Some(sandbox) = &entry.docker_sandbox {
            Collector::Sandbox(
                Arc::new(sandbox.for_observed_host(host)),
                entry.id.clone(),
                Some(native),
            )
        } else {
            Collector::Host(host, Some(native))
        }
    })
}
fn validate_execution_ids(request: &SpawnRequest) -> Result<()> {
    validate_id(&request.process)?;
    validate_id(&request.command.resource)
}
fn require_owned_collector(entry: &super::Resource) -> Result<()> {
    if entry.collector.is_none() {
        return Err(failure(
            tinybox_bus::UNSUPPORTED_OPERATION,
            "owned native collector unavailable",
        ));
    }
    Ok(())
}
fn select_execution_collector(
    entry: &super::Resource,
    jail: Option<&NativeJailRequest>,
    shell: Option<&tinybox_bus::ShellExecRequest>,
    resolved: &mut tinybox_core::ExecRequest,
) -> Result<CollectorPreparation> {
    Ok(if let Some(shell) = shell {
        if !entry.native_host || entry.local_sandbox.is_none() {
            return Err(failure(
                tinybox_bus::UNSUPPORTED_OPERATION,
                "native shell requires local passthrough execution",
            ));
        }
        let root = entry.workspace_root.as_ref().ok_or_else(|| {
            failure(
                tinybox_bus::UNSUPPORTED_OPERATION,
                "native shell requires directory resource",
            )
        })?;
        CollectorPreparation::Shell(Box::new((shell.clone(), root.clone(), resolved.clone())))
    } else {
        CollectorPreparation::Ready(select_collector(entry, jail, resolved)?)
    })
}
fn prepare_execution(
    entry: &super::Resource,
    request: &SpawnRequest,
    jail: Option<&NativeJailRequest>,
    shell: Option<&tinybox_bus::ShellExecRequest>,
    platform_shell: Option<&tinybox_bus::SelectShellRequest>,
) -> Result<(tinybox_core::ExecRequest, CollectorPreparation)> {
    if !entry.execution_supported
        || (entry.local_sandbox.is_none() && entry.docker_sandbox.is_none())
    {
        return Err(failure(
            tinybox_bus::UNSUPPORTED_OPERATION,
            "live output is unavailable for this provider",
        ));
    }
    require_owned_collector(entry)?;
    // Each execution owns its cleanup collector. Cancelling one stream must
    // not drain an unrelated running supervisor or inherit its failure.
    // Resolve before consuming admission, and fence native start against Close.
    if platform_shell.is_some() && (!entry.native_host || entry.local_sandbox.is_none()) {
        return Err(failure(
            tinybox_bus::UNSUPPORTED_OPERATION,
            "platform shell execution requires local passthrough",
        ));
    }
    let mut native_request = command(request.command.clone());
    if platform_shell.is_some() {
        // Resolve resource cwd and environment; the shell builder supplies argv.
        native_request.argv = vec!["shell".into()];
    }
    let mut resolved = if let Some(sandbox) = &entry.local_sandbox {
        sandbox
            .resolve_command(&entry.id, &native_request)
            .map_err(|error| backend_error(&error))?
    } else {
        let command = native_request;
        if command.argv.is_empty() {
            return Err(failure(tinybox_bus::INVALID_ID, "empty execution command"));
        }
        command
    };
    let collector = if let Some(shell) = platform_shell {
        CollectorPreparation::Ready(Collector::PlatformShell(
            Arc::new(tinybox_host::LimitedLocalHost::new(
                tinybox_bus::MAX_OUTPUT_BYTES,
            )),
            shell.clone(),
        ))
    } else {
        select_execution_collector(entry, jail, shell, &mut resolved)?
    };
    Ok((resolved, collector))
}
impl StreamExecution {
    fn check_replay(
        &self,
        request: &SpawnRequest,
        jail: Option<&NativeJailRequest>,
        shell: Option<&tinybox_bus::ShellExecRequest>,
        platform_shell: Option<&tinybox_bus::SelectShellRequest>,
    ) -> Result<()> {
        // Native shell identity is its original wire request; synthesized argv
        // can change when platform discovery changes between delivery retries.
        let same_request = shell.is_some() || self.request == *request;
        if same_request
            && self.jail.as_ref() == jail
            && self.shell.as_ref() == shell
            && self.platform_shell.as_ref() == platform_shell
        {
            Ok(())
        } else {
            Err(failure(
                tinybox_bus::INVALID_ID,
                "stream identifier belongs to another command",
            ))
        }
    }
    fn start(
        request: SpawnRequest,
        resolved: tinybox_core::ExecRequest,
        collector: Collector,
        jail: Option<NativeJailRequest>,
        shell: Option<tinybox_bus::ShellExecRequest>,
        platform_shell: Option<tinybox_bus::SelectShellRequest>,
    ) -> Self {
        let journal = Arc::new(OutputJournal::default());
        let observer = journal.clone();
        let runner = collector.clone();
        let timeout = shell.as_ref().map(|request| request.timeout_ms);
        let timed_out = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let timeout_outcome = timed_out.clone();
        let task = tokio::spawn(async move {
            let _completion = CompletionGuard(observer.clone());
            let result = if let Some(timeout) = timeout {
                if let Ok(result) = tokio::time::timeout(
                    std::time::Duration::from_millis(timeout),
                    runner.run(&resolved, observer.clone()),
                )
                .await
                {
                    Some(result)
                } else {
                    timeout_outcome.store(true, std::sync::atomic::Ordering::SeqCst);
                    let _cleanup = runner.drain().await;
                    None
                }
            } else {
                Some(runner.run(&resolved, observer.clone()).await)
            };
            if runner.pending() {
                observer.finish_failed(ExecutionFailure::CleanupFailed);
            } else if observer.cancel_requested() {
                observer.finish_exit(0);
            } else if result.is_none() {
                observer.finish_failed(ExecutionFailure::TimedOut);
            } else {
                match result {
                    Some(Ok(output)) => observer.finish_exit(output.exit_code),
                    Some(Err(tinybox_core::Error::OutputLimitExceeded { .. })) => {
                        observer.finish_failed(ExecutionFailure::OutputLimit);
                    }
                    Some(Err(_)) | None => observer.finish_failed(ExecutionFailure::BackendFailed),
                }
            }
        });
        Self {
            request,
            platform_shell,
            shell,
            jail,
            journal,
            task: Mutex::new(Some(task)),
            collector,
            timed_out,
        }
    }
    pub(super) fn running(&self) -> bool {
        !self.journal.cleanup_acknowledged()
    }
    pub(super) fn cleanup_acknowledged(&self) -> bool {
        self.journal.cleanup_acknowledged() && !self.collector.pending()
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
        self.collector.drain().await.map_err(|_| {
            failure(
                tinybox_bus::BACKEND_ERROR,
                "native stream cleanup remains pending",
            )
        })?;
        if !self.journal.cleanup_acknowledged() {
            let failure = if self.timed_out.load(std::sync::atomic::Ordering::SeqCst) {
                ExecutionFailure::TimedOut
            } else {
                ExecutionFailure::BackendFailed
            };
            self.journal.finish_failed(failure);
        }
        Ok(())
    }
    async fn dispose(&self) -> Result<()> {
        self.stop().await?;
        if let Collector::Shell(shell) = &self.collector {
            shell.dispose_scratch().await.map_err(|_| {
                failure(
                    tinybox_bus::BACKEND_ERROR,
                    "shell scratch cleanup remains pending",
                )
            })?;
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
        self.start_with_jail(request, None, None, None).await
    }
    pub(in crate::tinybus_module) async fn start_jailed_exec(
        &self,
        request: SpawnRequest,
        config: tinybox_bus::NativeJailConfig,
    ) -> Result<ProcessRef> {
        self.start_with_jail(request, Some(NativeJailRequest::Legacy(config)), None, None)
            .await
    }
    pub(in crate::tinybus_module) async fn start_jailed_exec_with_resources(
        &self,
        request: SpawnRequest,
        config: tinybox_bus::NativeJailRequest,
    ) -> Result<ProcessRef> {
        self.start_with_jail(
            request,
            Some(NativeJailRequest::Resources(config)),
            None,
            None,
        )
        .await
    }
    pub(in crate::tinybus_module) async fn start_shell_exec(
        &self,
        shell: tinybox_bus::ShellExecRequest,
    ) -> Result<ProcessRef> {
        let request = SpawnRequest {
            process: shell.process.clone(),
            command: tinybox_bus::ExecRequest {
                resource: shell.resource.clone(),
                argv: vec![tinybox_host::select_shell(&shell.shell).program],
                cwd: shell.cwd.clone(),
                env: shell.extra_env.clone(),
                stdin: shell.stdin.clone(),
            },
        };
        self.start_with_jail(
            request,
            shell.jail.clone().map(NativeJailRequest::Legacy),
            Some(shell),
            None,
        )
        .await
    }
    pub(in crate::tinybus_module) async fn start_platform_shell_exec(
        &self,
        request: SpawnRequest,
        shell: tinybox_bus::SelectShellRequest,
    ) -> Result<ProcessRef> {
        if !request.command.argv.is_empty() {
            return Err(failure(
                tinybox_bus::INVALID_ID,
                "shell execution requires empty argv",
            ));
        }
        self.start_with_jail(request, None, None, Some(shell)).await
    }
    async fn start_with_jail(
        &self,
        request: SpawnRequest,
        jail: Option<NativeJailRequest>,
        shell: Option<tinybox_bus::ShellExecRequest>,
        platform_shell: Option<tinybox_bus::SelectShellRequest>,
    ) -> Result<ProcessRef> {
        self.start_with_preparation(
            request,
            jail,
            shell,
            platform_shell,
            CollectorPreparation::finish,
        )
        .await
    }
    async fn start_with_preparation<Fut>(
        &self,
        request: SpawnRequest,
        jail: Option<NativeJailRequest>,
        shell: Option<tinybox_bus::ShellExecRequest>,
        platform_shell: Option<tinybox_bus::SelectShellRequest>,
        prepare: impl FnOnce(CollectorPreparation) -> Fut,
    ) -> Result<ProcessRef>
    where
        Fut: std::future::Future<Output = Result<Collector>>,
    {
        validate_execution_ids(&request)?;
        let process = ProcessRef {
            resource: request.command.resource.clone(),
            process: request.process.clone(),
        };
        if let Some(existing) = self.stream(&process)? {
            existing.check_replay(
                &request,
                jail.as_ref(),
                shell.as_ref(),
                platform_shell.as_ref(),
            )?;
            return Ok(process);
        }
        let slot = self.slot(&process.resource).await?;
        let guard = slot.lock().await;
        let entry = guard
            .as_ref()
            .ok_or_else(|| failure(tinybox_bus::UNKNOWN_RESOURCE, "closed resource"))?;
        let _preparation = self.claim_preparation(entry, &request).await?;
        let (resolved, collector) = prepare_execution(
            entry,
            &request,
            jail.as_ref(),
            shell.as_ref(),
            platform_shell.as_ref(),
        )?;
        // Preparation owns its snapshot; Close must not wait for filesystem I/O.
        drop(guard);
        let collector = prepare(collector).await?;
        let admitted = async {
            let guard = slot.lock().await;
            let entry = guard
                .as_ref()
                .ok_or_else(|| failure(tinybox_bus::UNKNOWN_RESOURCE, "closed resource"))?;
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
                existing.check_replay(
                    &request,
                    jail.as_ref(),
                    shell.as_ref(),
                    platform_shell.as_ref(),
                )?;
                return Ok(false);
            }
            if entry.processes.len()
                + streams
                    .values()
                    .filter(|stream| stream.request.command.resource == process.resource)
                    .count()
                + self.stdio_count(&process.resource)
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
                Arc::new(StreamExecution::start(
                    request,
                    resolved,
                    collector.clone(),
                    jail,
                    shell,
                    platform_shell,
                )),
            );
            Ok(true)
        }
        .await;
        if !matches!(admitted, Ok(true)) {
            self.dispose_rejected_collector(&process.resource, collector)
                .await?;
        }
        admitted?;
        Ok(process)
    }

    async fn claim_preparation(
        &self,
        entry: &super::Resource,
        request: &SpawnRequest,
    ) -> Result<tokio::sync::SemaphorePermit<'_>> {
        let mut state = self.state.lock().await;
        let executions = self
            .executions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        check_resource_open(&state, &executions, &request.command.resource)?;
        self.check_reservation(
            &mut state,
            &request.process,
            &ReserveRequest::Process(request.command.resource.clone()),
        )?;
        let streams = self
            .streams
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let pending = MAX_STREAM_EXECUTIONS - self.preparations.available_permits();
        if streams.len() + pending >= MAX_STREAM_EXECUTIONS
            || entry.processes.len()
                + streams
                    .values()
                    .filter(|stream| stream.request.command.resource == request.command.resource)
                    .count()
                + self.stdio_count(&request.command.resource)
                >= tinybox_bus::MAX_PROCESSES_PER_RESOURCE
        {
            return Err(failure(
                tinybox_bus::RESOURCE_LIMIT,
                "execution preparation limit reached",
            ));
        }
        self.preparations.try_acquire().map_err(|_| {
            failure(
                tinybox_bus::RESOURCE_LIMIT,
                "execution preparation limit reached",
            )
        })
    }

    async fn dispose_rejected_collector(
        &self,
        resource: &ResourceId,
        collector: Collector,
    ) -> Result<()> {
        if let Collector::Shell(shell) = collector {
            // Retain ownership before awaiting cleanup, including if the caller cancels.
            self.rejected_shells
                .lock()
                .await
                .push((resource.clone(), shell));
            self.dispose_rejected_shells(Some(resource)).await?;
        }
        Ok(())
    }

    pub(super) async fn dispose_rejected_shells(
        &self,
        resource: Option<&ResourceId>,
    ) -> Result<()> {
        let mut shells = self.rejected_shells.lock().await;
        let mut index = 0;
        let mut error = None;
        while index < shells.len() {
            if resource.is_some_and(|resource| *resource != shells[index].0) {
                index += 1;
                continue;
            }
            if shells[index].1.dispose_scratch().await.is_ok() {
                shells.remove(index);
            } else {
                error.get_or_insert_with(|| {
                    failure(
                        tinybox_bus::BACKEND_ERROR,
                        "rejected shell scratch cleanup remains pending",
                    )
                });
                index += 1;
            }
        }
        error.map_or(Ok(()), Err)
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
        entry.processes.len() + self.streams_for(resource).len() + self.stdio_count(resource)
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
            if let Err(error) = stream.dispose().await {
                failure.get_or_insert(error);
            }
        }
        if self.stream_cleanup_pending(resource) {
            return Err(failure.unwrap_or_else(|| Error::failed("stream cleanup remains pending")));
        }
        self.retire_streams(resource);
        failure.map_or(Ok(()), Err)
    }
    pub(super) async fn close_destroyed_box_streams(
        &self,
        resource: &ResourceId,
        id: &tinybox_core::BoxId,
    ) -> Result<()> {
        // Only the caller that has just acknowledged resource-wide destruction
        // may retire a remote waiter's receipt. Individual Cancel never enters
        // this path; each native CLI owner must still join and drain normally.
        for stream in self.streams_for(resource) {
            stream.collector.acknowledge_destroyed_box(id);
        }
        self.close_streams(resource).await
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
            if !stream.journal.cleanup_acknowledged() {
                return Err(failure(
                    tinybox_bus::UNSUPPORTED_OPERATION,
                    "execution cleanup is not acknowledged",
                ));
            }
            stream.dispose().await?;
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
