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

    assert_eq!(description, describe(&registered_sandboxes()));
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
