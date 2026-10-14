//! Tests for the `TinyBus` module adapter and its declared surface.

use super::{
    BoxService, INTERFACE, OBJECT_PATH, Platform, capabilities_for, describe, registered_sandboxes,
    setup,
};
use tinybox_core::{IsolationLevel, SandboxCapabilities, SnapshotSupport};
use tinybus::broker::Broker;
use tinybus::transport::memory::MemoryBus;
use tinybus::{Connection, Interface};

/// A container-class backend, standing in for one a later milestone registers.
const CONTAINER: SandboxCapabilities =
    SandboxCapabilities::new(IsolationLevel::Kernel, SnapshotSupport::Filesystem)
        .with_fork()
        .with_port_forward()
        .with_resource_limits();

/// A backend too weak to be trusted with untrusted code.
const BARE: SandboxCapabilities = SandboxCapabilities::PASSTHROUGH;

#[tokio::test]
async fn command_facts_keep_quoted_heredoc_data_out_of_host_policy_inputs() -> tinybus::Result<()> {
    let analysis = BoxService::default()
        .analyze_command(
            "cat <<'EOF' > report.txt\nrm -rf /; $HOME/.ssh/id_rsa; $(curl bad.invalid)\nEOF\n"
                .into(),
        )
        .await?;
    assert!(analysis.redirection);
    assert!(!analysis.hidden_execution);
    assert!(!analysis.expansion);
    assert!(!analysis.background);
    // Preserve the existing scanner's delimiter segment and conservative
    // unknown-command category while excluding the document body.
    assert_eq!(analysis.segments.len(), 2);
    assert_eq!(analysis.segments[1].normalized_name, "eof");
    assert_eq!(analysis.segments[1].class, tinybox_bus::CommandClass::Write);
    assert_eq!(analysis.segments[0].normalized_name, "cat");
    assert_eq!(analysis.segments[0].class, tinybox_bus::CommandClass::Read);
    assert!(
        !analysis
            .literal_words
            .iter()
            .any(|word| word.contains(".ssh") || word.contains("curl"))
    );
    Ok(())
}

#[tokio::test]
async fn command_facts_preserve_global_install_and_environment_execution_signals()
-> tinybus::Result<()> {
    let analysis = BoxService::default()
        .analyze_command("LD_PRELOAD=./hook.so git status && npm install -g tool &".into())
        .await?;
    assert!(analysis.background);
    assert!(analysis.segments[0].leading_env_assignment);
    assert!(analysis.segments[0].dangerous_env_prefix);
    assert_eq!(analysis.segments[0].basename, "git");
    assert_eq!(
        analysis.segments[1].class,
        tinybox_bus::CommandClass::Install
    );
    Ok(())
}

#[tokio::test]
async fn jail_status_reports_the_detected_backend_without_starting_a_process() -> tinybus::Result<()>
{
    let status = BoxService::default().jail_status().await?;
    let backend = tinybox_jail::default_backend();
    assert_eq!(status.backend, backend.name());
    assert_eq!(status.available, backend.is_available());
    assert_eq!(status.isolation, backend.isolation().to_string());
    assert_eq!(
        status.suitable_for_untrusted_code,
        backend.is_suitable_for_untrusted_code()
    );
    assert_eq!(
        status.filesystem,
        backend
            .constraint_support()
            .enforcement(tinybox_core::Constraint::Filesystem)
            .to_string()
    );
    assert_eq!(
        status.network,
        backend
            .constraint_support()
            .enforcement(tinybox_core::Constraint::Network)
            .to_string()
    );
    assert_eq!(
        status.subprocess,
        backend
            .constraint_support()
            .enforcement(tinybox_core::Constraint::Subprocess)
            .to_string()
    );
    Ok(())
}

#[test]
fn backend_capabilities_match_supervision_and_confinement_platforms() {
    let other = capabilities_for(Platform::Other);
    assert_eq!(other.create_backends, ["passthrough"]);
    assert_eq!(other.exec_backends, Vec::<String>::new());
    assert_eq!(other.spawn_backends, Vec::<String>::new());

    let macos = capabilities_for(Platform::Unix);
    assert_eq!(macos.create_backends, ["passthrough", "docker"]);
    assert_eq!(macos.exec_backends, ["passthrough", "docker"]);
    assert_eq!(macos.spawn_backends, ["passthrough", "docker"]);

    let windows = capabilities_for(Platform::Windows);
    assert_eq!(windows.create_backends, ["passthrough", "docker"]);
    assert_eq!(windows.exec_backends, ["passthrough", "docker"]);
    assert_eq!(windows.spawn_backends, ["passthrough", "docker"]);

    let linux = capabilities_for(Platform::Linux);
    assert_eq!(
        linux.create_backends,
        ["passthrough", "docker", "namespace"]
    );
    assert_eq!(linux.exec_backends, ["passthrough", "docker"]);
    assert_eq!(linux.spawn_backends, ["passthrough", "docker"]);
}

#[test]
fn windows_advertises_only_backends_with_native_supervision() {
    assert!(super::supports_create_backend(
        Platform::Windows,
        "passthrough"
    ));
    assert!(super::supports_create_backend(Platform::Windows, "docker"));
    assert!(!super::supports_create_backend(
        Platform::Windows,
        "namespace"
    ));
    assert!(super::resources::supports_execution(
        Platform::Windows,
        "passthrough"
    ));
    assert!(super::resources::supports_execution(
        Platform::Windows,
        "docker"
    ));
    assert!(!super::resources::supports_execution(
        Platform::Windows,
        "namespace"
    ));
}

#[test]
fn terminal_shutdown_is_an_explicit_module_operation() {
    assert!(
        BoxService::default()
            .members()
            .iter()
            .any(|member| member.to_string() == "Shutdown")
    );
}

#[tokio::test]
async fn forwarding_methods_dispatch_and_unknown_close_is_idempotent() -> tinybus::Result<()> {
    let service = BoxService::default();
    assert!(
        service
            .forward(tinybox_bus::ForwardRequest {
                resource: tinybox_bus::ResourceId("missing-resource".into()),
                forward: tinybox_bus::ResourceId("reserved-forward".into()),
                guest_port: 8080,
            })
            .await
            .is_err()
    );
    service
        .close_forward(tinybox_bus::CloseForwardRequest {
            resource: tinybox_bus::ResourceId("missing-resource".into()),
            forward: tinybox_bus::ResourceId("reserved-forward".into()),
        })
        .await?;
    Ok(())
}

#[tokio::test]
async fn capabilities_and_shutdown_report_actual_supported_ownership() -> tinybus::Result<()> {
    let service = BoxService::default();
    let capabilities = service.capabilities().await?;
    let expected = capabilities_for(Platform::current());
    assert_eq!(capabilities.contract_version, tinybox_bus::CONTRACT_VERSION);
    assert_eq!(capabilities.create_backends, expected.create_backends);
    assert_eq!(capabilities.exec_backends, expected.exec_backends);
    assert_eq!(capabilities.spawn_backends, expected.spawn_backends);
    service.shutdown().await?;
    service.shutdown().await?;
    assert!(
        service
            .reserve(tinybox_bus::ReserveRequest::Resource)
            .await
            .is_err()
    );
    assert!(
        service
            .exec(tinybox_bus::ExecRequest {
                resource: tinybox_bus::ResourceId("retired".into()),
                argv: vec!["unused".into()],
                cwd: None,
                env: std::collections::BTreeMap::new(),
                stdin: None
            })
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn new_module_operations_dispatch_and_preserve_validation_errors() -> tinybus::Result<()> {
    let service = BoxService::default();

    let abort = service
        .abort_file_write(tinybox_bus::AbortFileWriteRequest {
            resource: tinybox_bus::ResourceId("missing-resource".into()),
            transfer: tinybox_bus::ResourceId("missing-transfer".into()),
        })
        .await;
    assert!(abort.is_err());

    let jailed = service
        .start_jailed_exec(
            tinybox_bus::SpawnRequest {
                process: tinybox_bus::ResourceId("process".into()),
                command: tinybox_bus::ExecRequest {
                    resource: tinybox_bus::ResourceId("missing-resource".into()),
                    argv: vec!["true".into()],
                    cwd: None,
                    env: std::collections::BTreeMap::new(),
                    stdin: None,
                },
            },
            tinybox_bus::NativeJailConfig {
                read_only: Vec::new(),
                read_write: Vec::new(),
                unix_paths: tinybox_bus::UnixPathGrants::default(),
                allow_net: false,
                allow_subprocess: false,
                enforcement: tinybox_bus::JailEnforcement::Declared,
                require_process_isolation: false,
            },
        )
        .await;
    assert!(jailed.is_err());

    let docker = service
        .run_docker(tinybox_bus::DockerRunRequest {
            workspace: "/workspace".into(),
            image: None,
            command: "true".into(),
            login_shell: false,
            network: None,
            memory_limit_mb: None,
            cpus: None,
            read_only_rootfs: None,
            read_only_mounts: Vec::new(),
            extra_cap_drops: Vec::new(),
            env: std::collections::BTreeMap::new(),
            label: None,
            timeout_ms: tinybox_bus::MAX_DOCKER_RUN_TIMEOUT_MS + 1,
        })
        .await;
    assert!(docker.is_err());

    let docker_without_workspace = service
        .run_docker_without_workspace(tinybox_bus::DockerRunRequest {
            workspace: "/must/not/be/mounted".into(),
            image: None,
            command: "true".into(),
            login_shell: false,
            network: None,
            memory_limit_mb: None,
            cpus: None,
            read_only_rootfs: None,
            read_only_mounts: Vec::new(),
            extra_cap_drops: Vec::new(),
            env: std::collections::BTreeMap::new(),
            label: None,
            timeout_ms: 1000,
        })
        .await;
    assert!(docker_without_workspace.is_err());
    Ok(())
}

#[test]
fn declared_methods_match_the_dispatch_table() {
    let mut methods = BoxService::default()
        .members()
        .into_iter()
        .map(|member| member.to_string())
        .collect::<Vec<_>>();

    methods.sort_unstable();
    let mut declared = tinybox_bus::METHODS.to_vec();
    declared.sort_unstable();
    assert_eq!(methods, declared);
}

#[test]
fn an_empty_registry_is_reported_as_none_rather_than_omitted() {
    // A build with no backends must say so plainly rather than leaving the
    // reader to infer it from an absent list.
    let description = describe(&[]);

    assert!(description.contains(env!("CARGO_PKG_VERSION")));
    assert!(description.contains("kernel"));
    assert!(description.contains("sandboxes: none"));
    assert!(description.ends_with("none"));
}

#[test]
fn the_registry_reports_every_backend_and_only_the_safe_ones_as_capable() {
    let description = describe(&registered_sandboxes());

    // Both backends are listed as present...
    assert!(description.contains("sandboxes: passthrough, docker, namespace, microvm"));
    // ...but only Docker clears the isolation floor, and passthrough says so
    // through its own declaration rather than a special case here.
    assert!(description.ends_with("docker, namespace, microvm"));

    let names = registered_sandboxes()
        .into_iter()
        .map(|(name, _)| name)
        .collect::<Vec<_>>();
    assert_eq!(names, ["passthrough", "docker", "namespace", "microvm"]);
}

#[test]
fn a_populated_registry_lists_every_sandbox() {
    let description = describe(&[("docker", CONTAINER), ("namespace", CONTAINER)]);

    assert!(description.contains("sandboxes: docker, namespace"));
}

#[test]
fn only_sandboxes_above_the_isolation_floor_are_called_untrusted_capable() {
    let description = describe(&[("passthrough", BARE), ("docker", CONTAINER)]);

    // Both are listed as present...
    assert!(description.contains("sandboxes: passthrough, docker"));
    // ...but only the one that actually confines anything is recommended.
    assert!(description.ends_with("docker"));
    assert!(!description.ends_with("passthrough, docker"));
}

#[test]
fn a_registry_of_only_weak_sandboxes_recommends_nothing() {
    let description = describe(&[("passthrough", BARE)]);

    assert!(description.contains("sandboxes: passthrough"));
    assert!(description.ends_with("none"));
}

#[tokio::test]
async fn module_describes_itself_over_a_real_bus() -> tinybus::Result<()> {
    let bus = MemoryBus::new();
    Broker::new().spawn(bus.clone());

    let service = Connection::connect(bus.connect().await?).await?;
    setup(service.clone()).await?;

    let client = Connection::connect(bus.connect().await?).await?;
    let proxy = client.proxy(INTERFACE, OBJECT_PATH, INTERFACE)?;
    let description: String = proxy.call("Describe", ()).await?;
    let status: tinybox_bus::JailStatus = proxy.call("JailStatus", ()).await?;
    assert_ne!(status.backend, "");
    if !status.available || status.isolation == "none" {
        assert!(!status.suitable_for_untrusted_code);
    }

    assert_eq!(description, describe(&registered_sandboxes()));
    Ok(())
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one broker fixture verifies the complete serialized file-transfer path"
)]
async fn workspace_file_transfers_roundtrip_through_the_bus_codec() -> tinybus::Result<()> {
    use tinybox_bus::{
        BeginFileReadRequest, BeginFileWriteRequest, CreateRequest, FileChunk,
        FinishFileReadRequest, FinishFileWriteRequest, ReadFileChunkRequest, ReserveRequest,
        ResourceInfo, Workspace, WriteFileChunkRequest,
    };

    let workspace = tempfile::tempdir()
        .map_err(|error| tinybus::Error::failed(format!("create workspace fixture: {error}")))?;
    let bus = MemoryBus::new();
    Broker::new().spawn(bus.clone());
    let service = Connection::connect(bus.connect().await?).await?;
    setup(service.clone()).await?;
    let client = Connection::connect(bus.connect().await?).await?;
    let proxy = client.proxy(INTERFACE, OBJECT_PATH, INTERFACE)?;
    let resource: tinybox_bus::ResourceId =
        proxy.call("Reserve", (ReserveRequest::Resource,)).await?;
    let created: ResourceInfo = proxy
        .call(
            "Create",
            (CreateRequest {
                resource: resource.clone(),
                backend: "passthrough".into(),
                workspace: Workspace::Directory(workspace.path().to_string_lossy().into_owned()),
                ..Default::default()
            },),
        )
        .await?;
    let write: tinybox_bus::ResourceId = proxy
        .call("Reserve", (ReserveRequest::FileWrite(resource.clone()),))
        .await?;
    proxy
        .call::<tinybox_bus::FileWriteInfo>(
            "BeginFileWrite",
            (BeginFileWriteRequest {
                resource: resource.clone(),
                transfer: write.clone(),
                path: "report.bin".into(),
            },),
        )
        .await?;
    proxy
        .call::<tinybox_bus::FileWriteProgress>(
            "WriteFileChunk",
            (WriteFileChunkRequest {
                resource: resource.clone(),
                transfer: write.clone(),
                offset: 0,
                bytes: vec![0, 1, 0xff, 0x80],
            },),
        )
        .await?;
    proxy
        .call::<tinybox_bus::FileWriteProgress>(
            "FinishFileWrite",
            (FinishFileWriteRequest {
                resource: resource.clone(),
                transfer: write,
            },),
        )
        .await?;

    let read: tinybox_bus::ResourceId = proxy
        .call("Reserve", (ReserveRequest::FileRead(resource.clone()),))
        .await?;
    let traversal = proxy
        .call::<tinybox_bus::FileReadInfo>(
            "BeginFileRead",
            (BeginFileReadRequest {
                resource: resource.clone(),
                transfer: read.clone(),
                path: "../source.bin".into(),
            },),
        )
        .await;
    assert!(matches!(
        traversal,
        Err(tinybus::Error::MethodFailed { name, .. }) if name == tinybox_bus::INVALID_FILE_PATH
    ));
    proxy
        .call::<tinybox_bus::FileReadInfo>(
            "BeginFileRead",
            (BeginFileReadRequest {
                resource: resource.clone(),
                transfer: read.clone(),
                path: "report.bin".into(),
            },),
        )
        .await?;
    let chunk: FileChunk = proxy
        .call(
            "ReadFileChunk",
            (ReadFileChunkRequest {
                resource: resource.clone(),
                transfer: read.clone(),
                offset: 0,
                max_bytes: 4,
            },),
        )
        .await?;
    assert_eq!(chunk.bytes, [0, 1, 0xff, 0x80]);
    proxy
        .call::<()>(
            "FinishFileRead",
            (FinishFileReadRequest {
                resource: resource.clone(),
                transfer: read,
            },),
        )
        .await?;
    proxy.call::<()>("Close", (created.resource,)).await?;
    Ok(())
}

#[tokio::test]
async fn the_module_claims_its_well_known_name() -> tinybus::Result<()> {
    let bus = MemoryBus::new();
    Broker::new().spawn(bus.clone());

    let service = Connection::connect(bus.connect().await?).await?;
    setup(service.clone()).await?;

    let client = Connection::connect(bus.connect().await?).await?;
    let names = client.list_names().await?;

    assert!(
        names.iter().any(|name| name.as_str() == INTERFACE),
        "expected {INTERFACE} among {names:?}"
    );
    Ok(())
}

#[tokio::test]
async fn an_unknown_method_is_rejected() -> tinybus::Result<()> {
    let bus = MemoryBus::new();
    Broker::new().spawn(bus.clone());

    let service = Connection::connect(bus.connect().await?).await?;
    setup(service.clone()).await?;

    let client = Connection::connect(bus.connect().await?).await?;
    let proxy = client.proxy(INTERFACE, OBJECT_PATH, INTERFACE)?;
    let result = proxy.call::<String>("Snapshot", ()).await;

    assert!(
        result.is_err(),
        "a method outside the declared surface should be refused"
    );
    Ok(())
}

#[tokio::test]
async fn shell_analysis_preserves_quoted_heredoc_data() -> tinybus::Result<()> {
    let service = BoxService::default();
    let quoted = service
        .analyze_shell("cat > out << 'EOF'\n$(danger) &\nEOF\n".into())
        .await?;
    assert!(!quoted.hidden_execution);
    assert!(quoted.redirection);
    let unquoted = service
        .analyze_shell("cat << EOF\n$(danger)\nEOF\n".into())
        .await?;
    assert!(unquoted.hidden_execution);
    assert!(!unquoted.redirection);
    let heredoc_redirect = service
        .analyze_shell("cat << EOF\nbody > is data\nEOF\n".into())
        .await?;
    assert!(!heredoc_redirect.redirection);
    Ok(())
}

#[tokio::test]
async fn unknown_resources_and_unsupported_backends_are_refused() -> tinybus::Result<()> {
    use tinybox_bus::{CreateRequest, ExecRequest, ProcessRef, ResourceId, Workspace};
    let service = BoxService::default();
    let unknown = ResourceId("unissued".into());
    let command = ExecRequest {
        resource: unknown.clone(),
        argv: vec!["true".into()],
        cwd: None,
        env: std::collections::BTreeMap::new(),
        stdin: None,
    };
    let process = ProcessRef {
        resource: unknown.clone(),
        process: unknown.clone(),
    };
    assert!(service.exec(command.clone()).await.is_err());
    assert!(
        service
            .spawn(tinybox_bus::SpawnRequest {
                process: unknown.clone(),
                command
            })
            .await
            .is_err()
    );
    assert!(service.inspect(unknown.clone()).await.is_err());
    assert!(service.is_running(process.clone()).await.is_err());
    service.cancel(process).await?;
    service.close(unknown).await?;
    for backend in ["unknown", "microvm", ""] {
        assert!(
            service
                .create(CreateRequest {
                    resource: service
                        .reserve(tinybox_bus::ReserveRequest::Resource)
                        .await?,
                    backend: backend.into(),
                    workspace: Workspace::Directory(".".into()),
                    env: std::collections::BTreeMap::new(),
                    ..Default::default()
                })
                .await
                .is_err()
        );
    }
    assert!(
        service
            .create(CreateRequest {
                resource: service
                    .reserve(tinybox_bus::ReserveRequest::Resource)
                    .await?,
                backend: "passthrough".into(),
                workspace: Workspace::Image("alpine".into()),
                env: std::collections::BTreeMap::new(),
                ..Default::default()
            })
            .await
            .is_err()
    );
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn commands_and_detached_process_lifetimes_work_over_the_bus() -> tinybus::Result<()> {
    use tinybox_bus::{
        CreateRequest, ExecOutput, ExecRequest, ProcessRef, ResourceInfo, Workspace,
    };
    let bus = MemoryBus::new();
    Broker::new().spawn(bus.clone());
    let service = Connection::connect(bus.connect().await?).await?;
    setup(service.clone()).await?;
    let client = Connection::connect(bus.connect().await?).await?;
    let proxy = client.proxy(INTERFACE, OBJECT_PATH, INTERFACE)?;
    let created: ResourceInfo = proxy
        .call(
            "Create",
            (CreateRequest {
                resource: proxy
                    .call("Reserve", (tinybox_bus::ReserveRequest::Resource,))
                    .await?,
                backend: "passthrough".into(),
                workspace: Workspace::Directory(".".into()),
                env: std::collections::BTreeMap::new(),
                ..Default::default()
            },),
        )
        .await?;
    let inspected: ResourceInfo = proxy.call("Inspect", (created.resource.clone(),)).await?;
    assert_eq!(created, inspected);
    let command = ExecRequest {
        resource: created.resource.clone(),
        argv: vec![
            "sh".into(),
            "-c".into(),
            "printf hello; printf error >&2; exit 7".into(),
        ],
        cwd: None,
        env: std::collections::BTreeMap::new(),
        stdin: None,
    };
    let output: ExecOutput = proxy.call("Exec", (command.clone(),)).await?;
    assert_eq!(output.exit_code, 7);
    assert_eq!(output.stdout, b"hello");
    assert_eq!(output.stderr, b"error");
    let input = ExecRequest {
        resource: created.resource.clone(),
        argv: vec!["cat".into()],
        cwd: Some(".".into()),
        env: std::collections::BTreeMap::new(),
        stdin: Some(vec![0, 255, 42]),
    };
    let bytes: ExecOutput = proxy.call("Exec", (input,)).await?;
    assert_eq!(bytes.stdout, [0, 255, 42]);

    let mut background = command;
    background.argv = vec!["sleep".into(), "600".into()];
    let process: ProcessRef = proxy
        .call(
            "Spawn",
            (tinybox_bus::SpawnRequest {
                process: proxy
                    .call(
                        "Reserve",
                        (tinybox_bus::ReserveRequest::Process(
                            created.resource.clone(),
                        ),),
                    )
                    .await?,
                command: background.clone(),
            },),
        )
        .await?;
    assert!(proxy.call::<bool>("IsRunning", (process.clone(),)).await?);
    proxy.call::<()>("Cancel", (process.clone(),)).await?;
    assert!(!proxy.call::<bool>("IsRunning", (process.clone(),)).await?);
    proxy.call::<()>("Cancel", (process,)).await?;
    let process: ProcessRef = proxy
        .call(
            "Spawn",
            (tinybox_bus::SpawnRequest {
                process: proxy
                    .call(
                        "Reserve",
                        (tinybox_bus::ReserveRequest::Process(
                            created.resource.clone(),
                        ),),
                    )
                    .await?,
                command: background,
            },),
        )
        .await?;
    proxy
        .call::<()>("Close", (created.resource.clone(),))
        .await?;
    assert!(
        proxy
            .call::<ResourceInfo>("Inspect", (created.resource.clone(),))
            .await
            .is_err()
    );
    assert!(proxy.call::<bool>("IsRunning", (process,)).await.is_err());
    proxy.call::<()>("Close", (created.resource,)).await?;
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn cleanup_retires_known_reservations_even_before_startup() -> tinybus::Result<()> {
    use tinybox_bus::{
        CreateRequest, ExecRequest, ProcessRef, ResourceId, SpawnRequest, Workspace,
    };
    let service = BoxService::default();
    let resource = service
        .reserve(tinybox_bus::ReserveRequest::Resource)
        .await?;
    let request = CreateRequest {
        resource: resource.clone(),
        backend: "passthrough".into(),
        workspace: Workspace::Directory(".".into()),
        env: std::collections::BTreeMap::new(),
        ..Default::default()
    };
    service.close(resource.clone()).await?;
    assert!(service.create(request.clone()).await.is_err());
    let mut request = request;
    request.resource = service
        .reserve(tinybox_bus::ReserveRequest::Resource)
        .await?;
    service.create(request.clone()).await?;
    assert!(service.create(request.clone()).await.is_err());
    let process = ProcessRef {
        resource: request.resource.clone(),
        process: service
            .reserve(tinybox_bus::ReserveRequest::Process(
                request.resource.clone(),
            ))
            .await?,
    };
    service.cancel(process.clone()).await?;
    let command = ExecRequest {
        resource: request.resource.clone(),
        argv: vec!["sleep".into(), "600".into()],
        cwd: None,
        env: std::collections::BTreeMap::new(),
        stdin: None,
    };
    assert!(
        service
            .spawn(SpawnRequest {
                process: process.process,
                command: command.clone()
            })
            .await
            .is_err()
    );
    let process = service
        .reserve(tinybox_bus::ReserveRequest::Process(
            request.resource.clone(),
        ))
        .await?;
    service
        .spawn(SpawnRequest {
            process: process.clone(),
            command,
        })
        .await?;
    service
        .cancel(ProcessRef {
            resource: request.resource.clone(),
            process,
        })
        .await?;
    service.close(request.resource.clone()).await?;
    assert!(service.create(request).await.is_err());
    let empty = ResourceId(String::new());
    assert!(service.close(empty.clone()).await.is_err());
    assert!(
        service
            .cancel(ProcessRef {
                resource,
                process: empty.clone()
            })
            .await
            .is_err()
    );
    assert!(
        service
            .create(CreateRequest {
                resource: empty,
                backend: "passthrough".into(),
                workspace: Workspace::Directory(".".into()),
                env: std::collections::BTreeMap::new(),
                ..Default::default()
            })
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn bounded_live_output_roundtrips_through_the_bus_codec() -> tinybus::Result<()> {
    use tinybox_bus::{
        CreateRequest, ExecRequest, ExecutionState, OutputBatch, ProcessRef, ReserveRequest,
        ResourceId, SpawnRequest, Workspace,
    };
    let bus = MemoryBus::new();
    Broker::new().spawn(bus.clone());
    let service = Connection::connect(bus.connect().await?).await?;
    setup(service.clone()).await?;
    let client = Connection::connect(bus.connect().await?).await?;
    let proxy = client.proxy(INTERFACE, OBJECT_PATH, INTERFACE)?;
    let resource: ResourceId = proxy.call("Reserve", (ReserveRequest::Resource,)).await?;
    proxy
        .call::<tinybox_bus::ResourceInfo>(
            "Create",
            (CreateRequest {
                resource: resource.clone(),
                backend: "passthrough".into(),
                workspace: Workspace::Directory(".".into()),
                ..Default::default()
            },),
        )
        .await?;
    let process: ResourceId = proxy
        .call("Reserve", (ReserveRequest::Process(resource.clone()),))
        .await?;
    #[cfg(windows)]
    let argv = vec!["cmd".into(), "/C".into(), "echo live & exit 7".into()];
    #[cfg(not(windows))]
    let argv = vec!["/bin/sh".into(), "-c".into(), "printf live; exit 7".into()];
    let process: ProcessRef = proxy
        .call(
            "StartExec",
            (SpawnRequest {
                process,
                command: ExecRequest {
                    resource: resource.clone(),
                    argv,
                    cwd: None,
                    env: std::collections::BTreeMap::new(),
                    stdin: None,
                },
            },),
        )
        .await?;
    let output: OutputBatch = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let output: OutputBatch = proxy.call("ReadOutput", (process.clone(), 0_u64)).await?;
            if output.state != ExecutionState::Running {
                return Ok::<_, tinybus::Error>(output);
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| tinybus::Error::failed("live output fixture timed out"))??;
    assert_eq!(output.state, ExecutionState::Exited { exit_code: 7 });
    let bytes: Vec<u8> = output
        .chunks
        .iter()
        .flat_map(|chunk| chunk.bytes.iter().copied())
        .collect();
    assert_eq!(String::from_utf8_lossy(&bytes).trim(), "live");
    proxy
        .call::<()>("ReleaseOutput", (process.clone(),))
        .await?;
    assert!(
        proxy
            .call::<OutputBatch>("ReadOutput", (process, 0_u64))
            .await
            .is_err()
    );
    proxy.call::<()>("Close", (resource,)).await?;
    Ok(())
}

#[tokio::test]
async fn local_grant_discovery_refuses_home_ancestors_of_credentials()
-> Result<(), Box<dyn std::error::Error>> {
    let home = tempfile::tempdir()?;
    std::fs::create_dir(home.path().join(".ssh"))?;
    std::fs::create_dir(home.path().join("data"))?;
    let service = BoxService::default();
    let result = service
        .resolve_local_grants(tinybox_bus::ResolveLocalGrantsRequest {
            home: Some(home.path().to_str().ok_or("home is not UTF-8")?.into()),
            config: tinybox_bus::LocalGrantConfig {
                toolchain_homes: false,
                extra_read_only: vec!["~".into(), "~/.ssh".into(), "~/data".into()],
                ..tinybox_bus::LocalGrantConfig::default()
            },
            protected: tinybox_bus::ProtectedPaths {
                components: vec![".ssh".into()],
                credential_roots: vec![
                    home.path()
                        .join(".ssh")
                        .to_str()
                        .ok_or("credential root is not UTF-8")?
                        .into(),
                ],
                ..tinybox_bus::ProtectedPaths::default()
            },
            allow_unix_paths: false,
        })
        .await?;
    assert_eq!(
        result.read_only,
        vec![
            home.path()
                .join("data")
                .canonicalize()?
                .to_str()
                .ok_or("grant is not UTF-8")?
        ]
    );
    assert_eq!(result.read_write, Vec::<String>::new());
    Ok(())
}

#[tokio::test]
async fn local_grant_discovery_rejects_excessive_requested_grants() {
    let result = BoxService::default()
        .resolve_local_grants(tinybox_bus::ResolveLocalGrantsRequest {
            home: None,
            config: tinybox_bus::LocalGrantConfig {
                extra_read_only: vec!["/missing".into(); tinybox_bus::MAX_NATIVE_JAIL_GRANTS + 1],
                ..tinybox_bus::LocalGrantConfig::default()
            },
            protected: tinybox_bus::ProtectedPaths::default(),
            allow_unix_paths: false,
        })
        .await;
    assert!(result.is_err());
}

#[test]
#[cfg(unix)]
fn local_grant_discovery_rejects_non_utf8_canonical_targets()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::ffi::OsStringExt;
    // APFS refuses invalid UTF-8 filenames. Supply the canonical path directly
    // at the serialization boundary instead of depending on filesystem encoding.
    let target = std::path::PathBuf::from(std::ffi::OsString::from_vec(vec![b'/', b'd', 0xff]));
    let error = super::grant_paths_to_wire(vec!["/valid".into(), target], false)
        .err()
        .ok_or("non-UTF8 grant must be rejected")?;
    assert_eq!(error.wire_name(), tinybox_bus::INVALID_FILE_PATH);
    Ok(())
}

#[test]
#[cfg(unix)]
fn opted_in_local_grants_keep_non_utf8_paths_as_raw_bytes() -> Result<(), Box<dyn std::error::Error>>
{
    use std::os::unix::ffi::OsStringExt;
    let target = std::path::PathBuf::from(std::ffi::OsString::from_vec(vec![b'/', b'd', 0xff]));
    let (utf8, unix) = super::grant_paths_to_wire(vec!["/valid".into(), target], true)?;
    assert_eq!(utf8, vec!["/valid"]);
    assert_eq!(unix, vec![vec![b'/', b'd', 0xff]]);
    Ok(())
}

#[tokio::test]
async fn local_grant_discovery_bounds_final_toolchain_and_extra_grants()
-> Result<(), Box<dyn std::error::Error>> {
    let home = tempfile::tempdir()?;
    std::fs::create_dir(home.path().join(".rustup"))?;
    let mut extra_read_only = Vec::new();
    for index in 0..tinybox_bus::MAX_NATIVE_JAIL_GRANTS {
        let path = home.path().join(format!("data-{index}"));
        std::fs::create_dir(&path)?;
        extra_read_only.push(path.to_str().ok_or("grant is not UTF-8")?.into());
    }
    let result = BoxService::default()
        .resolve_local_grants(tinybox_bus::ResolveLocalGrantsRequest {
            home: Some(home.path().to_str().ok_or("home is not UTF-8")?.into()),
            config: tinybox_bus::LocalGrantConfig {
                extra_read_only,
                ..tinybox_bus::LocalGrantConfig::default()
            },
            protected: tinybox_bus::ProtectedPaths::default(),
            allow_unix_paths: false,
        })
        .await;
    assert!(
        matches!(result, Err(tinybus::Error::MethodFailed { ref name, .. }) if name.as_str() == tinybox_bus::RESOURCE_LIMIT)
    );
    Ok(())
}

#[tokio::test]
async fn local_grant_discovery_accepts_exactly_the_final_limit()
-> Result<(), Box<dyn std::error::Error>> {
    let home = tempfile::tempdir()?;
    let mut extra_read_only = Vec::new();
    for index in 0..tinybox_bus::MAX_NATIVE_JAIL_GRANTS {
        let path = home.path().join(format!("data-{index}"));
        std::fs::create_dir(&path)?;
        extra_read_only.push(path.to_str().ok_or("grant is not UTF-8")?.into());
    }
    let result = BoxService::default()
        .resolve_local_grants(tinybox_bus::ResolveLocalGrantsRequest {
            home: Some(home.path().to_str().ok_or("home is not UTF-8")?.into()),
            config: tinybox_bus::LocalGrantConfig {
                toolchain_homes: false,
                extra_read_only,
                ..tinybox_bus::LocalGrantConfig::default()
            },
            protected: tinybox_bus::ProtectedPaths::default(),
            allow_unix_paths: false,
        })
        .await?;
    assert_eq!(result.read_only.len(), tinybox_bus::MAX_NATIVE_JAIL_GRANTS);
    assert_eq!(result.read_write, Vec::<String>::new());
    Ok(())
}

#[tokio::test]
async fn unsupported_git_include_expansions_refuse_the_whole_discovery()
-> Result<(), Box<dyn std::error::Error>> {
    for include in ["~other/shared.conf", "%(prefix)/shared.conf"] {
        let home = tempfile::tempdir()?;
        std::fs::write(
            home.path().join(".gitconfig"),
            format!("[include]\npath = {include}\n"),
        )?;
        let result = BoxService::default()
            .resolve_local_grants(tinybox_bus::ResolveLocalGrantsRequest {
                home: Some(home.path().to_str().ok_or("non-UTF8 fixture")?.into()),
                config: tinybox_bus::LocalGrantConfig::default(),
                protected: tinybox_bus::ProtectedPaths::default(),
                allow_unix_paths: false,
            })
            .await;
        assert!(
            matches!(result, Err(tinybus::Error::MethodFailed { ref name, .. }) if name.as_str() == tinybox_bus::UNSUPPORTED_OPERATION),
            "{include}: {result:?}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn native_shell_selection_and_execution_roundtrip_through_the_bus_codec()
-> Result<(), Box<dyn std::error::Error>> {
    let state = tempfile::tempdir()?;
    let bus = MemoryBus::new();
    Broker::new().spawn(bus.clone());
    let service = Connection::connect(bus.connect().await?).await?;
    setup(service.clone()).await?;
    let client = Connection::connect(bus.connect().await?).await?;
    let proxy = client.proxy(INTERFACE, OBJECT_PATH, INTERFACE)?;
    let shell = tinybox_bus::SelectShellRequest {
        command: "echo native".into(),
        preserve_pipeline_status: false,
        runtime_path: None,
        python_utf8: false,
    };
    let selection: tinybox_bus::ShellInvocation =
        proxy.call("SelectShell", (shell.clone(),)).await?;
    assert_eq!(selection, tinybox_host::select_shell(&shell));
    let resource: tinybox_bus::ResourceId = proxy
        .call("Reserve", (tinybox_bus::ReserveRequest::Resource,))
        .await?;
    proxy
        .call::<tinybox_bus::ResourceInfo>(
            "Create",
            (tinybox_bus::CreateRequest {
                resource: resource.clone(),
                backend: "passthrough".into(),
                workspace: tinybox_bus::Workspace::Directory(".".into()),
                ..Default::default()
            },),
        )
        .await?;
    let process = proxy
        .call(
            "Reserve",
            (tinybox_bus::ReserveRequest::Process(resource.clone()),),
        )
        .await?;
    let process: tinybox_bus::ProcessRef = proxy
        .call(
            "StartNativeShellExec",
            (tinybox_bus::ShellExecRequest {
                process,
                resource: resource.clone(),
                shell,
                cwd: None,
                extra_env: std::collections::BTreeMap::new(),
                state_dir: state.path().to_str().ok_or("non-UTF8 state")?.into(),
                timeout_ms: 5000,
                stdin: None,
                jail: None,
                hide_window: false,
            },),
        )
        .await?;
    let output = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let batch: tinybox_bus::OutputBatch =
                proxy.call("ReadOutput", (process.clone(), 0_u64)).await?;
            if batch.state != tinybox_bus::ExecutionState::Running {
                break Ok::<_, tinybus::Error>(batch);
            }
            tokio::task::yield_now().await;
        }
    })
    .await??;
    assert_eq!(
        output.state,
        tinybox_bus::ExecutionState::Exited { exit_code: 0 }
    );
    let bytes: Vec<u8> = output
        .chunks
        .iter()
        .flat_map(|chunk| chunk.bytes.clone())
        .collect();
    assert_eq!(String::from_utf8_lossy(&bytes).trim(), "native");
    proxy.call::<()>("ReleaseOutput", (process,)).await?;
    assert_eq!(
        std::fs::read_dir(state.path().join("artifacts/sandbox-scratch"))?.count(),
        0
    );
    proxy.call::<()>("Close", (resource,)).await?;
    Ok(())
}

#[tokio::test]
async fn existing_shell_method_keeps_its_two_argument_bus_codec()
-> Result<(), Box<dyn std::error::Error>> {
    let bus = MemoryBus::new();
    Broker::new().spawn(bus.clone());
    let service = Connection::connect(bus.connect().await?).await?;
    setup(service.clone()).await?;
    let client = Connection::connect(bus.connect().await?).await?;
    let proxy = client.proxy(INTERFACE, OBJECT_PATH, INTERFACE)?;
    let shell = tinybox_bus::SelectShellRequest {
        command: "echo native".into(),
        preserve_pipeline_status: false,
        runtime_path: None,
        python_utf8: false,
    };
    let selection: tinybox_bus::ShellInvocation =
        proxy.call("SelectShell", (shell.clone(),)).await?;
    assert_eq!(selection, tinybox_host::select_shell(&shell));
    let resource: tinybox_bus::ResourceId = proxy
        .call("Reserve", (tinybox_bus::ReserveRequest::Resource,))
        .await?;
    proxy
        .call::<tinybox_bus::ResourceInfo>(
            "Create",
            (tinybox_bus::CreateRequest {
                resource: resource.clone(),
                backend: "passthrough".into(),
                workspace: tinybox_bus::Workspace::Directory(".".into()),
                ..Default::default()
            },),
        )
        .await?;
    let process = proxy
        .call(
            "Reserve",
            (tinybox_bus::ReserveRequest::Process(resource.clone()),),
        )
        .await?;
    let process: tinybox_bus::ProcessRef = proxy
        .call(
            "StartShellExec",
            (
                tinybox_bus::SpawnRequest {
                    process,
                    command: tinybox_bus::ExecRequest {
                        resource: resource.clone(),
                        argv: Vec::new(),
                        cwd: None,
                        env: std::collections::BTreeMap::new(),
                        stdin: None,
                    },
                },
                shell,
            ),
        )
        .await?;
    let output = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let batch: tinybox_bus::OutputBatch =
                proxy.call("ReadOutput", (process.clone(), 0_u64)).await?;
            if batch.state != tinybox_bus::ExecutionState::Running {
                break Ok::<_, tinybus::Error>(batch);
            }
            tokio::task::yield_now().await;
        }
    })
    .await??;
    assert_eq!(
        output.state,
        tinybox_bus::ExecutionState::Exited { exit_code: 0 }
    );
    let bytes: Vec<u8> = output
        .chunks
        .iter()
        .flat_map(|chunk| chunk.bytes.clone())
        .collect();
    assert_eq!(String::from_utf8_lossy(&bytes).trim(), "native");
    proxy.call::<()>("ReleaseOutput", (process,)).await?;
    proxy.call::<()>("Close", (resource,)).await?;
    Ok(())
}

#[tokio::test]
async fn shell_discovery_preserves_the_requested_pipeline_status() -> tinybus::Result<()> {
    let service = BoxService::default();
    let selected = service
        .select_shell(tinybox_bus::SelectShellRequest {
            command: "false | true".into(),
            preserve_pipeline_status: true,
            runtime_path: None,
            python_utf8: false,
        })
        .await?;
    if cfg!(windows) {
        assert_eq!(selected.flavor, tinybox_bus::ShellFlavor::Cmd);
        assert_eq!(selected.raw_arguments.as_deref(), Some("\"false | true\""));
    } else {
        assert_eq!(selected.flavor, tinybox_bus::ShellFlavor::Posix);
        assert_eq!(
            selected.arguments.last().map(String::as_str),
            Some("false | true")
        );
    }
    Ok(())
}

#[tokio::test]
async fn docker_control_dispatch_rejects_unbounded_deadlines() {
    let service = BoxService::default();
    let status = service
        .docker_status(tinybox_bus::DockerStatusRequest { timeout_ms: 0 })
        .await;
    assert!(
        matches!(status, Err(tinybus::Error::MethodFailed { name, .. })
        if name == tinybox_bus::INVALID_DOCKER_CONTROL)
    );
    let cleanup = service
        .cleanup_docker(tinybox_bus::CleanupDockerRequest {
            label: "openhuman.sandbox=true".into(),
            timeout_ms: tinybox_bus::MAX_DOCKER_CONTROL_TIMEOUT_MS + 1,
        })
        .await;
    assert!(
        matches!(cleanup, Err(tinybus::Error::MethodFailed { name, .. })
        if name == tinybox_bus::INVALID_DOCKER_CONTROL)
    );
}

#[tokio::test]
async fn validate_docker_policy_reports_the_run_checks_without_a_daemon()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let service = BoxService::default();
    let safe = service
        .validate_docker_policy(tinybox_bus::DockerPolicyRequest {
            network: Some("none".into()),
            workspace: Some("/home/u/project".into()),
            read_only_mounts: vec!["/usr/lib".into()],
        })
        .await?;
    assert_eq!(safe.issues, Vec::<String>::new());

    let unsafe_run = service
        .validate_docker_policy(tinybox_bus::DockerPolicyRequest {
            network: Some("host".into()),
            workspace: Some("/".into()),
            read_only_mounts: vec!["/etc/".into(), "/var/run/docker.sock".into()],
        })
        .await?;
    assert_eq!(unsafe_run.issues.len(), 4);
    assert!(unsafe_run.issues[0].contains("host network"));
    Ok(())
}
