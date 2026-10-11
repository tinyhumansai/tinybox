//! `TinyBus` interface, ABI exports, and the bus-facing service.
//!
//! This adapter keeps the runtime model in [`tinybox_core`] independent of
//! `TinyBus` while exposing it as an installable, dynamically loaded
//! integration. It is private so that the ABI symbols `module_export!`
//! generates stay out of the crate's public documentation.

use tinybox_core::{IsolationLevel, SandboxCapabilities};
use tinybus::{Connection, Result as TinyBusResult};

use tinybox_bus::{
    CloseForwardRequest, CreateRequest, ExecOutput, ExecRequest, ForwardInfo, ForwardRequest,
    INTERFACE, OBJECT_PATH, ProcessRef, ResourceId, ResourceInfo, ShellAnalysis, SpawnRequest,
};

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
    /// Report native jail enforcement facts without starting a workload.
    #[expect(clippy::unused_async, reason = "TinyBus methods are asynchronous")]
    #[expect(
        clippy::unused_async_trait_impl,
        reason = "TinyBus methods are asynchronous"
    )]
    async fn jail_status(&self) -> TinyBusResult<tinybox_bus::JailStatus> {
        let backend = tinybox_jail::default_backend();
        let support = backend.constraint_support();
        Ok(tinybox_bus::JailStatus {
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
        })
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
    /// Report which operations own native cleanup on this platform.
    #[expect(
        clippy::unused_async,
        reason = "TinyBus exposes every interface method as an async operation"
    )]
    #[expect(
        clippy::unused_async_trait_impl,
        reason = "TinyBus exposes every interface method as an async operation"
    )]
    async fn capabilities(&self) -> TinyBusResult<tinybox_bus::ModuleCapabilities> {
        Ok(capabilities_for(Platform::current()))
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
    #[expect(
        clippy::unused_async,
        reason = "TinyBus exposes every interface method as an async operation"
    )]
    #[expect(
        clippy::unused_async_trait_impl,
        reason = "TinyBus exposes every interface method as an async operation"
    )]
    async fn analyze_shell(&self, command: String) -> TinyBusResult<ShellAnalysis> {
        use tinybox_core::shell::{classify, scan};
        let stripped = scan::strip_quoted_heredoc_bodies(&command);
        let structural = scan::strip_heredoc_bodies(&command);
        Ok(ShellAnalysis {
            segments: scan::split_unquoted_segments(&stripped),
            hidden_execution: classify::has_hidden_execution(&command),
            redirection: scan::contains_unquoted_char(&structural, '>'),
        })
    }

    /// Report what this build of tinybox can do.
    ///
    /// Returns the crate version followed by the sandboxes registered in this
    /// build, so a caller can tell whether the backend it needs is present
    /// before it tries to create a box.
    #[expect(
        clippy::unused_async,
        reason = "TinyBus exposes every interface method as an async operation"
    )]
    #[expect(
        clippy::unused_async_trait_impl,
        reason = "TinyBus exposes every interface method as an async operation"
    )]
    async fn describe(&self) -> TinyBusResult<String> {
        Ok(describe(&registered_sandboxes()))
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
    methods = ["Describe", "Create", "Exec", "Inspect", "Close", "Spawn", "IsRunning", "Cancel", "AnalyzeShell", "Reserve", "Capabilities", "Shutdown", "Forward", "CloseForward"],
    signals = [],
    requires = [],
    optional = [],
    lazy = false,
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod test;
