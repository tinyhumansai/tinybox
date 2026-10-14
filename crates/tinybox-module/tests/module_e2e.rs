//! End-to-end proof for the compiled `TinyBox` module's workspace file contract.

use std::time::Duration;

use tinybox_bus::{
    BeginFileReadRequest, BeginFileWriteRequest, CreateRequest, FileChunk, FinishFileReadRequest,
    FinishFileWriteRequest, ReadFileChunkRequest, ReserveRequest, ResourceId, ResourceInfo,
    Workspace, WriteFileChunkRequest,
};
use tinybus::Connection;
use tinybus::broker::Broker;
use tinybus::module::{ModuleHost, ModuleState};
use tinybus::transport::memory::MemoryBus;

const BUS_NAME: &str = "ai.tinyhumans.tinybox.Box";
const OBJECT_PATH: &str = "/ai/tinyhumans/tinybox/Box";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TINYBOX_TEST_MODULE to point at the built cdylib"]
#[expect(
    clippy::too_many_lines,
    reason = "the compiled artifact proof keeps manifest, broker, transfer, and cleanup assertions in one fixture"
)]
async fn compiled_module_transfers_workspace_files_over_a_broker()
-> Result<(), Box<dyn std::error::Error>> {
    let artifact = std::env::var_os("TINYBOX_TEST_MODULE")
        .ok_or("TINYBOX_TEST_MODULE must point at libtinybox")?;
    let workspace = tempfile::tempdir()?;
    let input = workspace.path().join("source.bin");
    let output = workspace.path().join("nested/output.bin");
    let payload = (0_u8..=255).cycle().take(150_000).collect::<Vec<u8>>();
    std::fs::write(&input, &payload)?;

    let bus = MemoryBus::new();
    let broker = Broker::new();
    let broker_task = broker.spawn(bus.clone());
    let modules = ModuleHost::new(broker);
    let loaded = modules.load_file(artifact)?;
    assert_eq!(loaded.name, "tinybox-module");
    assert_eq!(loaded.manifest.bus_name.as_str(), BUS_NAME);
    assert_eq!(loaded.manifest.object_path.as_str(), OBJECT_PATH);
    let declared: Vec<&str> = loaded
        .manifest
        .provides
        .iter()
        .flat_map(|interface| interface.methods.iter())
        .map(tinybus::MemberName::as_str)
        .collect();
    assert_eq!(declared, tinybox_bus::METHODS);

    let client = Connection::connect(bus.connect().await?).await?;
    wait_until_serving(&client, &modules).await?;
    let proxy = client.proxy(BUS_NAME, OBJECT_PATH, BUS_NAME)?;
    let capabilities: tinybox_bus::ModuleCapabilities = proxy.call("Capabilities", ()).await?;
    assert_eq!(capabilities.contract_version, tinybox_bus::CONTRACT_VERSION);
    let resource: ResourceId = proxy.call("Reserve", (ReserveRequest::Resource,)).await?;
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

    let reader: ResourceId = proxy
        .call("Reserve", (ReserveRequest::FileRead(resource.clone()),))
        .await?;
    let read_info: tinybox_bus::FileReadInfo = proxy
        .call(
            "BeginFileRead",
            (BeginFileReadRequest {
                resource: resource.clone(),
                transfer: reader.clone(),
                path: "source.bin".into(),
            },),
        )
        .await?;
    assert_eq!(read_info.size, payload.len() as u64);
    let mut offset = 0_u64;
    let writer: ResourceId = proxy
        .call("Reserve", (ReserveRequest::FileWrite(resource.clone()),))
        .await?;
    proxy
        .call::<tinybox_bus::FileWriteInfo>(
            "BeginFileWrite",
            (BeginFileWriteRequest {
                resource: resource.clone(),
                transfer: writer.clone(),
                path: "nested/output.bin".into(),
            },),
        )
        .await?;
    while offset < read_info.size {
        let chunk: FileChunk = proxy
            .call(
                "ReadFileChunk",
                (ReadFileChunkRequest {
                    resource: resource.clone(),
                    transfer: reader.clone(),
                    offset,
                    max_bytes: tinybox_bus::MAX_FILE_CHUNK_BYTES,
                },),
            )
            .await?;
        assert_eq!(chunk.offset, offset);
        assert_ne!(chunk.bytes, Vec::<u8>::new());
        let progress: tinybox_bus::FileWriteProgress = proxy
            .call(
                "WriteFileChunk",
                (WriteFileChunkRequest {
                    resource: resource.clone(),
                    transfer: writer.clone(),
                    offset,
                    bytes: chunk.bytes.clone(),
                },),
            )
            .await?;
        offset = offset
            .checked_add(chunk.bytes.len() as u64)
            .ok_or("transfer offset overflow")?;
        assert_eq!(progress.next_offset, offset);
    }
    proxy
        .call::<tinybox_bus::FileWriteProgress>(
            "FinishFileWrite",
            (FinishFileWriteRequest {
                resource: resource.clone(),
                transfer: writer,
            },),
        )
        .await?;
    proxy
        .call::<()>(
            "FinishFileRead",
            (FinishFileReadRequest {
                resource: resource.clone(),
                transfer: reader,
            },),
        )
        .await?;
    assert_eq!(std::fs::read(&output)?, payload);
    #[cfg(unix)]
    verify_live_output(&proxy, &resource).await?;
    #[cfg(unix)]
    verify_native_jail(&proxy, &resource).await?;
    proxy.call::<()>("Close", (created.resource,)).await?;
    wait_until_idle(&modules).await?;
    broker_task.abort();
    Ok(())
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TINYBOX_TEST_MODULE to point at the built cdylib"]
#[expect(
    clippy::too_many_lines,
    reason = "the compiled artifact proof verifies both existing and no-workspace Docker calls through one broker"
)]
async fn compiled_module_runs_one_shot_docker_through_a_broker()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/docker")
        .canonicalize()?;
    let path = std::env::var_os("PATH").ok_or("PATH is required")?;
    let selected = std::env::split_paths(&path)
        .find_map(|directory| {
            let candidate = directory.join("docker");
            candidate.is_file().then_some(candidate)
        })
        .ok_or("local Docker transport fixture is required")?;
    assert_eq!(
        selected.canonicalize()?,
        fixture,
        "refuse real Docker transport"
    );
    let artifact = std::env::var_os("TINYBOX_TEST_MODULE")
        .ok_or("TINYBOX_TEST_MODULE must point at libtinybox")?;
    let workspace = tempfile::tempdir()?;

    let bus = MemoryBus::new();
    let broker = Broker::new();
    let broker_task = broker.spawn(bus.clone());
    let modules = ModuleHost::new(broker);
    let loaded = modules.load_file(artifact)?;
    assert_eq!(loaded.name, "tinybox-module");
    let declared: Vec<&str> = loaded
        .manifest
        .provides
        .iter()
        .flat_map(|interface| interface.methods.iter())
        .map(tinybus::MemberName::as_str)
        .collect();
    assert_eq!(declared, tinybox_bus::METHODS);

    let client = Connection::connect(bus.connect().await?).await?;
    wait_until_serving(&client, &modules).await?;
    let proxy = client.proxy(BUS_NAME, OBJECT_PATH, BUS_NAME)?;
    let status: tinybox_bus::DockerStatus = proxy
        .call(
            "DockerStatus",
            (tinybox_bus::DockerStatusRequest { timeout_ms: 5_000 },),
        )
        .await?;
    assert!(status.available, "the local fixture answers Docker info");
    let cleanup: tinybox_bus::CleanupDockerOutput = proxy
        .call(
            "CleanupDocker",
            (tinybox_bus::CleanupDockerRequest {
                label: "openhuman.sandbox=true".into(),
                timeout_ms: 5_000,
            },),
        )
        .await?;
    assert_eq!(cleanup.containers_stopped, 1);
    let result: tinybox_bus::DockerRunOutput = proxy
        .call(
            "RunDocker",
            (tinybox_bus::DockerRunRequest {
                workspace: workspace.path().display().to_string(),
                image: None,
                command: "ignored by fixture".into(),
                login_shell: false,
                network: None,
                memory_limit_mb: None,
                cpus: None,
                read_only_rootfs: None,
                read_only_mounts: Vec::new(),
                extra_cap_drops: Vec::new(),
                env: std::collections::BTreeMap::new(),
                label: None,
                timeout_ms: 120_000,
            },),
        )
        .await?;
    assert_eq!(result.exit_code, 0);
    assert_eq!(result.stdout, "fixture-container\n");
    assert_eq!(result.stderr, "");
    assert!(!result.timed_out);
    let unmounted: tinybox_bus::DockerRunOutput = proxy
        .call(
            "RunDockerWithoutWorkspace",
            (tinybox_bus::DockerRunRequest {
                workspace: String::new(),
                image: None,
                command: "ignored by fixture".into(),
                login_shell: true,
                network: None,
                memory_limit_mb: None,
                cpus: None,
                read_only_rootfs: None,
                read_only_mounts: Vec::new(),
                extra_cap_drops: Vec::new(),
                env: std::collections::BTreeMap::new(),
                label: None,
                timeout_ms: 120_000,
            },),
        )
        .await?;
    assert_eq!(unmounted.exit_code, 0);
    assert_eq!(unmounted.stdout, "fixture-container\n");
    assert_eq!(unmounted.stderr, "");
    assert!(!unmounted.timed_out);
    modules.shutdown(Duration::from_secs(5)).await;
    broker_task.abort();
    Ok(())
}

/// The caller prepends the checked-in local SSH fixture to PATH before starting
/// this process; no runtime environment mutation or real SSH server is needed.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TINYBOX_TEST_MODULE and the local SSH fixture first on PATH"]
async fn compiled_module_streams_ssh_output_and_acknowledges_remote_cancellation()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/ssh")
        .canonicalize()?;
    let path = std::env::var_os("PATH").ok_or("PATH is required")?;
    let selected = std::env::split_paths(&path)
        .find_map(|directory| {
            let candidate = directory.join("ssh");
            candidate.is_file().then_some(candidate)
        })
        .ok_or("local SSH transport fixture is required")?;
    assert_eq!(
        selected.canonicalize()?,
        fixture,
        "refuse real SSH transport"
    );
    let artifact = std::env::var_os("TINYBOX_TEST_MODULE")
        .ok_or("TINYBOX_TEST_MODULE must point at libtinybox")?;
    // Give this independently loaded module its own native-library identity;
    // another artifact fixture may load the original path concurrently.
    let artifact_directory = tempfile::tempdir()?;
    let isolated_artifact = artifact_directory.path().join(
        std::path::Path::new(&artifact)
            .file_name()
            .ok_or("module filename is required")?,
    );
    std::fs::copy(artifact, &isolated_artifact)?;
    let workspace = tempfile::tempdir()?;
    let bus = MemoryBus::new();
    let broker = Broker::new();
    let broker_task = broker.spawn(bus.clone());
    let modules = ModuleHost::new(broker);
    modules.load_file(isolated_artifact)?;
    let client = Connection::connect(bus.connect().await?).await?;
    wait_until_serving(&client, &modules).await?;
    let proxy = client.proxy(BUS_NAME, OBJECT_PATH, BUS_NAME)?;
    let resource: ResourceId = proxy.call("Reserve", (ReserveRequest::Resource,)).await?;
    proxy
        .call::<ResourceInfo>(
            "Create",
            (CreateRequest {
                resource: resource.clone(),
                backend: "passthrough".into(),
                host: tinybox_bus::HostConfig::Ssh(tinybox_bus::SshHostConfig {
                    destination: "fixture.invalid".into(),
                    port: None,
                    identity: None,
                    known_hosts: None,
                    accept_new_host_key: false,
                }),
                workspace: Workspace::Directory(workspace.path().to_string_lossy().into_owned()),
                ..Default::default()
            },),
        )
        .await?;
    verify_live_output(&proxy, &resource).await?;
    verify_binary_stdin(&proxy, &resource).await?;
    proxy.call::<()>("Close", (resource,)).await?;
    wait_until_idle(&modules).await?;
    broker_task.abort();
    Ok(())
}

/// The caller prepends the checked-in local Docker fixture to PATH before starting
/// this process; no runtime environment mutation or real Docker server is needed.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TINYBOX_TEST_MODULE and the local Docker fixture first on PATH"]
async fn compiled_module_streams_docker_output_and_acknowledges_container_cancellation()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/docker")
        .canonicalize()?;
    let path = std::env::var_os("PATH").ok_or("PATH is required")?;
    let selected = std::env::split_paths(&path)
        .find_map(|directory| {
            let candidate = directory.join("docker");
            candidate.is_file().then_some(candidate)
        })
        .ok_or("local Docker transport fixture is required")?;
    assert_eq!(
        selected.canonicalize()?,
        fixture,
        "refuse real Docker transport"
    );
    let artifact = std::env::var_os("TINYBOX_TEST_MODULE")
        .ok_or("TINYBOX_TEST_MODULE must point at libtinybox")?;
    // Give this independently loaded module its own native-library identity;
    // another artifact fixture may load the original path concurrently.
    let artifact_directory = tempfile::tempdir()?;
    let isolated_artifact = artifact_directory.path().join(
        std::path::Path::new(&artifact)
            .file_name()
            .ok_or("module filename is required")?,
    );
    std::fs::copy(artifact, &isolated_artifact)?;
    let workspace = tempfile::tempdir()?;
    let bus = MemoryBus::new();
    let broker = Broker::new();
    let broker_task = broker.spawn(bus.clone());
    let modules = ModuleHost::new(broker);
    modules.load_file(isolated_artifact)?;
    let client = Connection::connect(bus.connect().await?).await?;
    wait_until_serving(&client, &modules).await?;
    let proxy = client.proxy(BUS_NAME, OBJECT_PATH, BUS_NAME)?;
    let resource: ResourceId = proxy.call("Reserve", (ReserveRequest::Resource,)).await?;
    proxy
        .call::<ResourceInfo>(
            "Create",
            (CreateRequest {
                resource: resource.clone(),
                backend: "docker".into(),
                workspace: Workspace::Directory(workspace.path().to_string_lossy().into_owned()),
                ..Default::default()
            },),
        )
        .await?;
    verify_docker_rejects_local_jail(&proxy, &resource).await?;
    verify_live_output(&proxy, &resource).await?;
    verify_binary_stdin(&proxy, &resource).await?;
    verify_cancellation_is_scoped(&proxy, &resource).await?;
    proxy.call::<()>("Close", (resource,)).await?;
    wait_until_idle(&modules).await?;
    broker_task.abort();
    Ok(())
}

async fn wait_until_serving(
    client: &Connection,
    modules: &ModuleHost,
) -> Result<(), Box<dyn std::error::Error>> {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if client
                .list_names()
                .await?
                .iter()
                .any(|name| name.as_str() == BUS_NAME)
            {
                return Ok::<(), tinybus::Error>(());
            }
            if modules
                .list()
                .first()
                .is_some_and(|module| matches!(module.state, ModuleState::Faulted { .. }))
            {
                return Err(tinybus::Error::failed(
                    "TinyBox module faulted during startup",
                ));
            }
            tokio::task::yield_now().await;
        }
    })
    .await??;
    Ok(())
}

async fn wait_until_idle(modules: &ModuleHost) -> Result<(), Box<dyn std::error::Error>> {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let state = modules
                .list()
                .first()
                .map(|module| module.state.clone())
                .ok_or_else(|| tinybus::Error::failed("loaded TinyBox module disappeared"))?;
            match state {
                ModuleState::Ready => return Ok::<(), tinybus::Error>(()),
                ModuleState::Serving => tokio::task::yield_now().await,
                _ => return Err(tinybus::Error::failed("TinyBox module left service")),
            }
        }
    })
    .await??;
    Ok(())
}

#[cfg(unix)]
#[expect(
    clippy::too_many_lines,
    reason = "single compiled-artifact lifecycle fixture verifies output, replay and acknowledged cancellation"
)]
async fn verify_live_output(
    proxy: &tinybus::Proxy,
    resource: &ResourceId,
) -> Result<(), Box<dyn std::error::Error>> {
    use tinybox_bus::{
        ExecRequest, ExecutionState, OutputBatch, OutputStream, ProcessRef, SpawnRequest,
    };
    let process: ResourceId = proxy
        .call("Reserve", (ReserveRequest::Process(resource.clone()),))
        .await?;
    let request = SpawnRequest {
        process,
        command: ExecRequest {
            resource: resource.clone(),
            argv: vec![
                "/bin/sh".into(),
                "-c".into(),
                "printf '\\377\\000'; printf error >&2; exit 7".into(),
            ],
            cwd: None,
            env: std::collections::BTreeMap::default(),
            stdin: None,
        },
    };
    let process: ProcessRef = proxy.call("StartExec", (request.clone(),)).await?;
    assert_eq!(
        process,
        proxy.call::<ProcessRef>("StartExec", (request,)).await?
    );
    let batch: OutputBatch = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let batch: OutputBatch = proxy.call("ReadOutput", (process.clone(), 0_u64)).await?;
            if batch.state != ExecutionState::Running {
                return Ok::<_, tinybus::Error>(batch);
            }
            tokio::task::yield_now().await;
        }
    })
    .await??;
    assert_eq!(batch.state, ExecutionState::Exited { exit_code: 7 });
    let stdout: Vec<u8> = batch
        .chunks
        .iter()
        .filter(|chunk| chunk.stream == OutputStream::Stdout)
        .flat_map(|chunk| chunk.bytes.iter().copied())
        .collect();
    let stderr: Vec<u8> = batch
        .chunks
        .iter()
        .filter(|chunk| chunk.stream == OutputStream::Stderr)
        .flat_map(|chunk| chunk.bytes.iter().copied())
        .collect();
    assert_eq!(stdout, [255, 0]);
    assert_eq!(stderr, b"error");
    assert_eq!(
        batch,
        proxy
            .call::<OutputBatch>("ReadOutput", (process.clone(), 0_u64))
            .await?
    );
    proxy
        .call::<()>("ReleaseOutput", (process.clone(),))
        .await?;
    assert!(
        proxy
            .call::<OutputBatch>("ReadOutput", (process, 0_u64))
            .await
            .is_err()
    );

    let process: ResourceId = proxy
        .call("Reserve", (ReserveRequest::Process(resource.clone()),))
        .await?;
    let process: ProcessRef = proxy
        .call(
            "StartExec",
            (SpawnRequest {
                process,
                command: ExecRequest {
                    resource: resource.clone(),
                    argv: vec![
                        "/bin/sh".into(),
                        "-c".into(),
                        "printf ready; exec sleep 600".into(),
                    ],
                    cwd: None,
                    env: std::collections::BTreeMap::default(),
                    stdin: None,
                },
            },),
        )
        .await?;
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let batch: OutputBatch = proxy.call("ReadOutput", (process.clone(), 0_u64)).await?;
            if !batch.chunks.is_empty() {
                assert_eq!(batch.state, ExecutionState::Running);
                return Ok::<_, tinybus::Error>(());
            }
            tokio::task::yield_now().await;
        }
    })
    .await??;
    assert!(
        proxy
            .call::<()>("ReleaseOutput", (process.clone(),))
            .await
            .is_err()
    );
    proxy.call::<()>("Cancel", (process.clone(),)).await?;
    let batch: OutputBatch = proxy.call("ReadOutput", (process.clone(), 0_u64)).await?;
    assert_eq!(batch.state, ExecutionState::Cancelled);
    assert_eq!(
        batch
            .chunks
            .iter()
            .flat_map(|chunk| chunk.bytes.iter().copied())
            .collect::<Vec<_>>(),
        b"ready"
    );
    assert!(!proxy.call::<bool>("IsRunning", (process.clone(),)).await?);
    proxy.call::<()>("ReleaseOutput", (process,)).await?;
    Ok(())
}

#[cfg(unix)]
async fn verify_binary_stdin(
    proxy: &tinybus::Proxy,
    resource: &ResourceId,
) -> Result<(), Box<dyn std::error::Error>> {
    use tinybox_bus::{ExecRequest, ExecutionState, OutputBatch, ProcessRef, SpawnRequest};
    let input = vec![0, 1, 255, 0, 42];
    let process: ResourceId = proxy
        .call("Reserve", (ReserveRequest::Process(resource.clone()),))
        .await?;
    let process: ProcessRef = proxy
        .call(
            "StartExec",
            (SpawnRequest {
                process,
                command: ExecRequest {
                    resource: resource.clone(),
                    argv: vec!["/bin/cat".into()],
                    cwd: None,
                    env: std::collections::BTreeMap::default(),
                    stdin: Some(input.clone()),
                },
            },),
        )
        .await?;
    let batch: OutputBatch = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let batch: OutputBatch = proxy.call("ReadOutput", (process.clone(), 0_u64)).await?;
            if batch.state != ExecutionState::Running {
                return Ok::<_, tinybus::Error>(batch);
            }
            tokio::task::yield_now().await;
        }
    })
    .await??;
    assert_eq!(batch.state, ExecutionState::Exited { exit_code: 0 });
    assert_eq!(
        batch
            .chunks
            .iter()
            .flat_map(|chunk| chunk.bytes.iter().copied())
            .collect::<Vec<_>>(),
        input
    );
    proxy.call::<()>("ReleaseOutput", (process,)).await?;
    Ok(())
}

#[cfg(unix)]
async fn verify_native_jail(
    proxy: &tinybus::Proxy,
    resource: &ResourceId,
) -> Result<(), Box<dyn std::error::Error>> {
    use tinybox_bus::{
        ExecRequest, ExecutionState, JailEnforcement, NativeJailConfig, OutputBatch, ProcessRef,
        SpawnRequest,
    };
    let id: ResourceId = proxy
        .call("Reserve", (ReserveRequest::Process(resource.clone()),))
        .await?;
    let outside = tempfile::tempdir()?;
    let forbidden = outside.path().join("forbidden");
    let request = SpawnRequest {
        process: id,
        command: ExecRequest {
            resource: resource.clone(),
            argv: vec![
                "/bin/sh".into(),
                "-c".into(),
                "if printf escaped > \"$1\" 2>/dev/null; then exit 9; fi; printf confined".into(),
                "fixture".into(),
                forbidden.to_string_lossy().into_owned(),
            ],
            cwd: None,
            env: std::collections::BTreeMap::default(),
            stdin: None,
        },
    };
    let config = NativeJailConfig {
        read_only: ["/usr", "/bin", "/lib", "/lib64", "/dev"]
            .into_iter()
            .filter(|path| std::path::Path::new(path).exists())
            .map(str::to_owned)
            .collect(),
        read_write: vec![],
        unix_paths: tinybox_bus::UnixPathGrants::default(),
        allow_net: true,
        allow_subprocess: true,
        enforcement: JailEnforcement::Enforced,
        require_process_isolation: false,
    };
    let status: tinybox_bus::JailStatus = proxy.call("JailStatus", ()).await?;
    eprintln!(
        "native jail fixture: backend={} available={} filesystem={}",
        status.backend, status.available, status.filesystem
    );
    let started = proxy
        .call::<ProcessRef>("StartJailedExec", (request.clone(), config.clone()))
        .await;
    if status.available && status.filesystem == "enforced" {
        let process = started?;
        assert_eq!(
            proxy
                .call::<ProcessRef>("StartJailedExec", (request.clone(), config.clone()))
                .await?,
            process
        );
        let mut changed = config.clone();
        changed.require_process_isolation = true;
        assert!(
            proxy
                .call::<ProcessRef>("StartJailedExec", (request, changed))
                .await
                .is_err()
        );
        let batch: OutputBatch = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let batch: OutputBatch = proxy.call("ReadOutput", (process.clone(), 0_u64)).await?;
                if batch.state != ExecutionState::Running {
                    return Ok::<_, tinybus::Error>(batch);
                }
                tokio::task::yield_now().await;
            }
        })
        .await??;
        assert_eq!(batch.state, ExecutionState::Exited { exit_code: 0 });
        assert_eq!(
            batch
                .chunks
                .iter()
                .filter(|chunk| chunk.stream == tinybox_bus::OutputStream::Stdout)
                .flat_map(|chunk| chunk.bytes.iter().copied())
                .collect::<Vec<_>>(),
            b"confined"
        );
        proxy.call::<()>("ReleaseOutput", (process,)).await?;
        verify_jailed_cancel(proxy, resource, config).await?;
    } else {
        assert!(started.is_err());
    }
    assert!(!forbidden.exists());
    Ok(())
}

#[cfg(unix)]
async fn verify_jailed_cancel(
    proxy: &tinybus::Proxy,
    resource: &ResourceId,
    config: tinybox_bus::NativeJailConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    use tinybox_bus::{ExecRequest, ExecutionState, OutputBatch, ProcessRef, SpawnRequest};
    let process: ResourceId = proxy
        .call("Reserve", (ReserveRequest::Process(resource.clone()),))
        .await?;
    let process: ProcessRef = proxy
        .call(
            "StartJailedExec",
            (
                SpawnRequest {
                    process,
                    command: ExecRequest {
                        resource: resource.clone(),
                        argv: vec![
                            "/bin/sh".into(),
                            "-c".into(),
                            "printf ready; sleep 600".into(),
                        ],
                        cwd: None,
                        env: std::collections::BTreeMap::default(),
                        stdin: None,
                    },
                },
                config,
            ),
        )
        .await?;
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let batch: OutputBatch = proxy.call("ReadOutput", (process.clone(), 0_u64)).await?;
            if !batch.chunks.is_empty() {
                break;
            }
            assert_eq!(batch.state, ExecutionState::Running);
            tokio::task::yield_now().await;
        }
        proxy.call::<()>("Cancel", (process.clone(),)).await
    })
    .await??;
    let batch: OutputBatch = proxy.call("ReadOutput", (process.clone(), 0_u64)).await?;
    assert_eq!(batch.state, ExecutionState::Cancelled);
    assert!(!proxy.call::<bool>("IsRunning", (process.clone(),)).await?);
    proxy.call::<()>("ReleaseOutput", (process,)).await?;
    Ok(())
}

#[cfg(unix)]
async fn verify_docker_rejects_local_jail(
    proxy: &tinybus::Proxy,
    resource: &ResourceId,
) -> Result<(), Box<dyn std::error::Error>> {
    use tinybox_bus::{ExecRequest, JailEnforcement, NativeJailConfig, ProcessRef, SpawnRequest};
    let process: ResourceId = proxy
        .call("Reserve", (ReserveRequest::Process(resource.clone()),))
        .await?;
    let request = SpawnRequest {
        process,
        command: ExecRequest {
            resource: resource.clone(),
            argv: vec!["/bin/true".into()],
            cwd: None,
            env: std::collections::BTreeMap::default(),
            stdin: None,
        },
    };
    let result = proxy
        .call::<ProcessRef>(
            "StartJailedExec",
            (
                request.clone(),
                NativeJailConfig {
                    read_only: Vec::new(),
                    read_write: Vec::new(),
                    unix_paths: tinybox_bus::UnixPathGrants::default(),
                    allow_net: true,
                    allow_subprocess: true,
                    enforcement: JailEnforcement::Declared,
                    require_process_isolation: false,
                },
            ),
        )
        .await;
    assert_eq!(
        result
            .err()
            .ok_or("Docker admitted local jail execution")?
            .wire_name(),
        tinybox_bus::UNSUPPORTED_OPERATION
    );
    let process: ProcessRef = proxy.call("StartExec", (request,)).await?;
    proxy.call::<()>("Cancel", (process.clone(),)).await?;
    proxy.call::<()>("ReleaseOutput", (process,)).await?;
    Ok(())
}

#[cfg(unix)]
async fn verify_cancellation_is_scoped(
    proxy: &tinybus::Proxy,
    resource: &ResourceId,
) -> Result<(), Box<dyn std::error::Error>> {
    use tinybox_bus::{ExecRequest, ExecutionState, OutputBatch, ProcessRef, SpawnRequest};
    let mut processes = Vec::new();
    for _ in 0..2 {
        let process: ResourceId = proxy
            .call("Reserve", (ReserveRequest::Process(resource.clone()),))
            .await?;
        let process: ProcessRef = proxy
            .call(
                "StartExec",
                (SpawnRequest {
                    process,
                    command: ExecRequest {
                        resource: resource.clone(),
                        argv: vec![
                            "/bin/sh".into(),
                            "-c".into(),
                            "printf ready; exec sleep 600".into(),
                        ],
                        cwd: None,
                        env: std::collections::BTreeMap::default(),
                        stdin: None,
                    },
                },),
            )
            .await?;
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let batch: OutputBatch = proxy.call("ReadOutput", (process.clone(), 0_u64)).await?;
                if !batch.chunks.is_empty() {
                    assert_eq!(batch.state, ExecutionState::Running);
                    return Ok::<_, tinybus::Error>(());
                }
                tokio::task::yield_now().await;
            }
        })
        .await??;
        processes.push(process);
    }
    proxy.call::<()>("Cancel", (processes[0].clone(),)).await?;
    let other: OutputBatch = proxy
        .call("ReadOutput", (processes[1].clone(), 0_u64))
        .await?;
    assert_eq!(other.state, ExecutionState::Running);
    assert!(
        proxy
            .call::<bool>("IsRunning", (processes[1].clone(),))
            .await?
    );
    for process in processes {
        proxy.call::<()>("Cancel", (process.clone(),)).await?;
        let batch: OutputBatch = proxy.call("ReadOutput", (process.clone(), 0_u64)).await?;
        assert_eq!(batch.state, ExecutionState::Cancelled);
        proxy.call::<()>("ReleaseOutput", (process,)).await?;
    }
    Ok(())
}
