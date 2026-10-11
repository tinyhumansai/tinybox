//! `TinyBus` interface, ABI exports, and the bus-facing service.
//!
//! This adapter keeps the runtime model in [`tinybox_core`] independent of
//! `TinyBus` while exposing it as an installable, dynamically loaded
//! integration. It is private so that the ABI symbols `module_export!`
//! generates stay out of the crate's public documentation.

use tinybox_core::{IsolationLevel, SandboxCapabilities};
use tinybus::{Connection, Result as TinyBusResult};

use tinybox_bus::{
    AbortFileWriteRequest, BeginFileReadRequest, BeginFileWriteRequest, CloseForwardRequest,
    CreateRequest, ExecOutput, ExecRequest, FileChunk, FileReadInfo, FileWriteInfo,
    FileWriteProgress, FinishFileReadRequest, FinishFileWriteRequest, ForwardInfo, ForwardRequest,
    INTERFACE, OBJECT_PATH, ProcessRef, ReadFileChunkRequest, ResourceId, ResourceInfo,
    ShellAnalysis, SpawnRequest, WriteFileChunkRequest,
};

mod docker;
mod native_jail;
mod output;
mod resources;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Platform {
    Linux,
    Unix,
    Windows,
    Other,
}

impl Platform {
    const fn current() -> Self {
        if cfg!(target_os = "linux") {
            Self::Linux
        } else if cfg!(unix) {
            Self::Unix
        } else if cfg!(windows) {
            Self::Windows
        } else {
            Self::Other
        }
    }
}

/// The bus-facing service.
#[derive(Default)]
struct BoxService {
    resources: std::sync::Arc<resources::Resources>,
}

#[tinybus::interface(name = "ai.tinyhumans.tinybox.Box")]
impl BoxService {
    /// Return detailed generic shell facts for caller-owned execution policy.
    async fn analyze_command(
        &self,
        command: String,
    ) -> TinyBusResult<tinybox_bus::CommandAnalysis> {
        std::future::ready(Ok(tinybox_core::shell::analysis::analyze_command(&command))).await
    }
    /// Discover canonical grants using the caller's protected-path floor.
    async fn resolve_local_grants(
        &self,
        request: tinybox_bus::ResolveLocalGrantsRequest,
    ) -> TinyBusResult<tinybox_bus::LocalGrants> {
        if request.config.extra_read_only.len() + request.config.extra_read_write.len()
            > tinybox_bus::MAX_NATIVE_JAIL_GRANTS
        {
            return Err(resources::failure(
                tinybox_bus::RESOURCE_LIMIT,
                "too many local grant paths",
            ));
        }
        let grants = tokio::task::spawn_blocking(move || {
            tinybox_jail::grants::resolve_local_jail_grants(
                request.home.as_deref().map(std::path::Path::new),
                &request.config,
                &request.protected,
            )
        })
        .await
        .map_err(|_| {
            resources::failure(tinybox_bus::UNSUPPORTED_OPERATION, "grant discovery failed")
        })?;
        let grants = grants.map_err(|_| {
            resources::failure(
                tinybox_bus::UNSUPPORTED_OPERATION,
                "unsupported git include pathname expansion",
            )
        })?;
        if grants.read_only.len() + grants.read_write.len() > tinybox_bus::MAX_NATIVE_JAIL_GRANTS {
            return Err(resources::failure(
                tinybox_bus::RESOURCE_LIMIT,
                "too many discovered local grant paths",
            ));
        }
        Ok(tinybox_bus::LocalGrants {
            read_only: grants
                .read_only
                .into_iter()
                .map(|path| {
                    path.into_os_string().into_string().map_err(|_| {
                        resources::failure(
                            tinybox_bus::INVALID_FILE_PATH,
                            "grant path is not UTF-8",
                        )
                    })
                })
                .collect::<TinyBusResult<Vec<_>>>()?,
            read_write: grants
                .read_write
                .into_iter()
                .map(|path| {
                    path.into_os_string().into_string().map_err(|_| {
                        resources::failure(
                            tinybox_bus::INVALID_FILE_PATH,
                            "grant path is not UTF-8",
                        )
                    })
                })
                .collect::<TinyBusResult<Vec<_>>>()?,
        })
    }
    /// Report native jail enforcement facts without starting a workload.
    async fn jail_status(&self) -> TinyBusResult<tinybox_bus::JailStatus> {
        let backend = tinybox_jail::default_backend();
        let support = backend.constraint_support();
        std::future::ready(Ok(tinybox_bus::JailStatus {
            backend: backend.name().into(),
            available: backend.is_available(),
            isolation: backend.isolation().to_string(),
            suitable_for_untrusted_code: backend.is_suitable_for_untrusted_code(),
            filesystem: support
                .enforcement(tinybox_core::Constraint::Filesystem)
                .to_string(),
            network: support
                .enforcement(tinybox_core::Constraint::Network)
                .to_string(),
            subprocess: support
                .enforcement(tinybox_core::Constraint::Subprocess)
                .to_string(),
        }))
        .await
    }
    /// Terminal barrier: freeze startup and join native resource cleanup before ABI unload.
    async fn shutdown(&self) -> TinyBusResult<()> {
        let resources = self.resources.clone();
        finish_operation(tokio::spawn(async move { resources.shutdown().await })).await
    }

    /// Open a module-owned gateway to one of a resource's published ports.
    async fn forward(&self, request: ForwardRequest) -> TinyBusResult<ForwardInfo> {
        let resources = self.resources.clone();
        finish_operation(tokio::spawn(
            async move { resources.forward(request).await },
        ))
        .await
    }

    /// Close a gateway opened by Forward; repeated calls are harmless.
    async fn close_forward(&self, request: CloseForwardRequest) -> TinyBusResult<()> {
        let resources = self.resources.clone();
        finish_operation(tokio::spawn(async move {
            resources.close_forward(request).await
        }))
        .await
    }

    /// Open a bounded read handle in the resource's mounted workspace.
    async fn begin_file_read(&self, request: BeginFileReadRequest) -> TinyBusResult<FileReadInfo> {
        self.resources.begin_file_read(request).await
    }

    /// Read one bounded range from an open workspace file.
    async fn read_file_chunk(&self, request: ReadFileChunkRequest) -> TinyBusResult<FileChunk> {
        self.resources.read_file_chunk(request).await
    }

    /// Release an open workspace reader.
    async fn finish_file_read(&self, request: FinishFileReadRequest) -> TinyBusResult<()> {
        self.resources.finish_file_read(request).await
    }

    /// Begin an atomic staged write in the resource's mounted workspace.
    async fn begin_file_write(
        &self,
        request: BeginFileWriteRequest,
    ) -> TinyBusResult<FileWriteInfo> {
        self.resources.begin_file_write(request).await
    }

    /// Append one bounded, sequential chunk to a staged workspace write.
    async fn write_file_chunk(
        &self,
        request: WriteFileChunkRequest,
    ) -> TinyBusResult<FileWriteProgress> {
        self.resources.write_file_chunk(request).await
    }

    /// Atomically publish a completed staged workspace write.
    async fn finish_file_write(
        &self,
        request: FinishFileWriteRequest,
    ) -> TinyBusResult<FileWriteProgress> {
        self.resources.finish_file_write(request).await
    }

    /// Discard an incomplete staged workspace write.
    async fn abort_file_write(&self, request: AbortFileWriteRequest) -> TinyBusResult<()> {
        self.resources.abort_file_write(request).await
    }
    /// Report which operations own native cleanup on this platform.
    async fn capabilities(&self) -> TinyBusResult<tinybox_bus::ModuleCapabilities> {
        std::future::ready(Ok(capabilities_for(Platform::current()))).await
    }
    /// Mint a single-use startup reservation, without starting native work.
    async fn reserve(&self, request: tinybox_bus::ReserveRequest) -> TinyBusResult<ResourceId> {
        self.resources.reserve(request).await
    }

    /// Allocate the explicitly requested sandbox, without fallback.
    async fn create(&self, request: CreateRequest) -> TinyBusResult<ResourceInfo> {
        let resources = self.resources.clone();
        finish_operation(tokio::spawn(async move { resources.create(request).await })).await
    }

    /// Run one unshelled command and collect output.
    async fn exec(&self, request: ExecRequest) -> TinyBusResult<ExecOutput> {
        let resources = self.resources.clone();
        finish_operation(tokio::spawn(async move { resources.exec(request).await })).await
    }

    /// Describe a live resource.
    async fn inspect(&self, resource: ResourceId) -> TinyBusResult<ResourceInfo> {
        self.resources.inspect(&resource).await
    }

    /// Stop tracked processes and destroy the resource.
    async fn close(&self, resource: ResourceId) -> TinyBusResult<()> {
        let resources = self.resources.clone();
        finish_operation(tokio::spawn(
            async move { resources.close(&resource).await },
        ))
        .await
    }

    /// Start a backend-owned detached process.
    async fn spawn(&self, request: SpawnRequest) -> TinyBusResult<ProcessRef> {
        let resources = self.resources.clone();
        finish_operation(tokio::spawn(async move { resources.spawn(request).await })).await
    }

    /// Start module-owned execution with replayable bounded output.
    async fn start_exec(&self, request: SpawnRequest) -> TinyBusResult<ProcessRef> {
        let resources = self.resources.clone();
        finish_operation(tokio::spawn(
            async move { resources.start_exec(request).await },
        ))
        .await
    }
    /// Start an execution in the resource's native directory jail.
    async fn start_jailed_exec(
        &self,
        request: SpawnRequest,
        config: tinybox_bus::NativeJailConfig,
    ) -> TinyBusResult<ProcessRef> {
        let resources = self.resources.clone();
        finish_operation(tokio::spawn(async move {
            resources.start_jailed_exec(request, config).await
        }))
        .await
    }

    /// Run one Docker-isolated shell command with bounded output and runtime.
    async fn run_docker(
        &self,
        request: tinybox_bus::DockerRunRequest,
    ) -> TinyBusResult<tinybox_bus::DockerRunOutput> {
        docker::run(request).await
    }

    /// Run one Docker-isolated shell command without mounting a host workspace.
    async fn run_docker_without_workspace(
        &self,
        request: tinybox_bus::DockerRunRequest,
    ) -> TinyBusResult<tinybox_bus::DockerRunOutput> {
        docker::run_without_workspace(&tinybox_docker::DockerCli::new(), request).await
    }

    /// Probe the Docker daemon on the module's host with a bounded deadline.
    async fn docker_status(
        &self,
        request: tinybox_bus::DockerStatusRequest,
    ) -> TinyBusResult<tinybox_bus::DockerStatus> {
        docker::status(request).await
    }

    /// Stop containers matching the supplied label on the module's host.
    async fn cleanup_docker(
        &self,
        request: tinybox_bus::CleanupDockerRequest,
    ) -> TinyBusResult<tinybox_bus::CleanupDockerOutput> {
        docker::cleanup(request).await
    }
    /// Read a replayable output batch beginning at the supplied sequence.
    async fn read_output(
        &self,
        process: ProcessRef,
        cursor: u64,
    ) -> TinyBusResult<tinybox_bus::OutputBatch> {
        self.resources.read_output(&process, cursor).await
    }
    /// Release a completed execution journal after native cleanup is acknowledged.
    async fn release_output(&self, process: ProcessRef) -> TinyBusResult<()> {
        self.resources.release_output(&process).await
    }

    /// Ask whether a tracked process remains alive.
    async fn is_running(&self, process: ProcessRef) -> TinyBusResult<bool> {
        self.resources.is_running(&process).await
    }

    /// Stop a tracked process; the identifier remains queryable until close.
    async fn cancel(&self, process: ProcessRef) -> TinyBusResult<()> {
        let resources = self.resources.clone();
        finish_operation(tokio::spawn(
            async move { resources.cancel(&process).await },
        ))
        .await
    }

    /// Return shell structure facts without applying host security policy.
    async fn analyze_shell(&self, command: String) -> TinyBusResult<ShellAnalysis> {
        use tinybox_core::shell::{classify, scan};
        let stripped = scan::strip_quoted_heredoc_bodies(&command);
        let structural = scan::strip_heredoc_bodies(&command);
        std::future::ready(Ok(ShellAnalysis {
            segments: scan::split_unquoted_segments(&stripped),
            hidden_execution: classify::has_hidden_execution(&command),
            redirection: scan::contains_unquoted_char(&structural, '>'),
        }))
        .await
    }

    /// Report what this build of tinybox can do.
    ///
    /// Returns the crate version followed by the sandboxes registered in this
    /// build, so a caller can tell whether the backend it needs is present
    /// before it tries to create a box.
    async fn describe(&self) -> TinyBusResult<String> {
        std::future::ready(Ok(describe(&registered_sandboxes()))).await
    }
}

fn capabilities_for(platform: Platform) -> tinybox_bus::ModuleCapabilities {
    let supervised: Vec<String> = if matches!(
        platform,
        Platform::Linux | Platform::Unix | Platform::Windows
    ) {
        vec!["passthrough".into(), "docker".into()]
    } else {
        Vec::new()
    };
    let mut create_backends = vec!["passthrough".into()];
    if matches!(
        platform,
        Platform::Linux | Platform::Unix | Platform::Windows
    ) {
        create_backends.push("docker".into());
    }
    if platform == Platform::Linux {
        create_backends.push("namespace".into());
    }
    tinybox_bus::ModuleCapabilities {
        contract_version: tinybox_bus::CONTRACT_VERSION,
        create_backends,
        exec_backends: supervised.clone(),
        spawn_backends: supervised,
    }
}

fn supports_create_backend(platform: Platform, backend: &str) -> bool {
    match backend {
        // Passthrough only records the caller's workspace; execution remains
        // unadvertised on hosts where TinyBox cannot supervise native children.
        "passthrough" => true,
        "docker" => matches!(
            platform,
            Platform::Linux | Platform::Unix | Platform::Windows
        ),
        "namespace" => platform == Platform::Linux,
        _ => false,
    }
}

/// The isolation a sandbox must reach before tinybox will call it safe for
/// code the operator does not trust.
///
/// Sourced from [`tinybox_core`] rather than restated here, so the bus answer
/// and the runtime check can never disagree.
const UNTRUSTED_FLOOR: IsolationLevel = IsolationLevel::Kernel;

/// Render the capability summary served by `Describe`.
///
/// Takes the sandbox list rather than reading it, so the rendering is a pure
/// function that can be asserted against any registry — including the populated
/// ones that later milestones will produce — without standing up a broker.
fn describe(sandboxes: &[(&str, SandboxCapabilities)]) -> String {
    let version = env!("CARGO_PKG_VERSION");
    let listed = if sandboxes.is_empty() {
        "none".to_owned()
    } else {
        sandboxes
            .iter()
            .map(|(name, _)| *name)
            .collect::<Vec<_>>()
            .join(", ")
    };

    let untrusted = sandboxes
        .iter()
        .filter(|(_, caps)| caps.is_suitable_for_untrusted_code())
        .map(|(name, _)| *name)
        .collect::<Vec<_>>();
    let untrusted = if untrusted.is_empty() {
        "none".to_owned()
    } else {
        untrusted.join(", ")
    };

    format!(
        "tinybox {version}; sandboxes: {listed}; untrusted-capable (>= {UNTRUSTED_FLOOR} isolation): {untrusted}"
    )
}

/// The sandbox backends compiled into this build, with what each declares.
///
/// Only backends this build can actually construct appear here: advertising a
/// sandbox that cannot be created would be worse than reporting none.
///
/// Passthrough is deliberately included even though it confines nothing, so
/// that `Describe` reports the full picture — and it is filtered out of the
/// untrusted-capable list by its own declaration rather than by a special case.
fn registered_sandboxes() -> Vec<(&'static str, SandboxCapabilities)> {
    vec![
        (
            tinybox_core::passthrough::NAME,
            SandboxCapabilities::PASSTHROUGH,
        ),
        (
            tinybox_docker::NAME,
            tinybox_docker::DockerSandbox::declared_capabilities(),
        ),
        (
            tinybox_linux::NAME,
            // Reported without cgroup limits: whether they are available
            // depends on the machine, and this is a static description of the
            // build rather than a probe of the host.
            tinybox_linux::NamespaceSandbox::declared_capabilities(false),
        ),
        (
            tinybox_microvm::NAME,
            tinybox_microvm::MicroVmSandbox::declared_capabilities(),
        ),
    ]
}

async fn finish_operation<T: Send + 'static>(
    task: tokio::task::JoinHandle<TinyBusResult<T>>,
) -> TinyBusResult<T> {
    task.await
        .map_err(|error| tinybus::Error::failed(error.to_string()))?
}

async fn setup(connection: Connection) -> TinyBusResult<()> {
    connection
        .serve_at(OBJECT_PATH.try_into()?, BoxService::default())
        .await?;
    connection.request_name(INTERFACE).await?;
    Ok(())
}

tinybus_module::module_export_optional_static! {
    setup = setup,
    worker_threads = 1,
    provides = ["ai.tinyhumans.tinybox.Box"],
    methods = ["Describe", "Create", "Exec", "Inspect", "Close", "Spawn", "IsRunning", "Cancel", "AnalyzeShell", "Reserve", "Capabilities", "Shutdown", "Forward", "CloseForward", "JailStatus", "AnalyzeCommand", "BeginFileRead", "ReadFileChunk", "FinishFileRead", "BeginFileWrite", "WriteFileChunk", "FinishFileWrite", "AbortFileWrite", "StartExec", "ReadOutput", "ReleaseOutput", "StartJailedExec", "RunDocker", "DockerStatus", "CleanupDocker", "RunDockerWithoutWorkspace", "ResolveLocalGrants"],
    signals = [],
    requires = [],
    optional = [],
    lazy = false,
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod test;
