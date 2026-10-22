//! Interactive stdio runs real children behind a recording jail backend.
use super::*;
use std::sync::Mutex;
use tinybox_bus::{
    CreateRequest, ProcessRef, STDIO_CLOSED, StdioExit, StdioReadRequest, StdioWriteRequest,
    Workspace,
};
use tinybox_jail::Jail;

/// Spawns unconfined children but declares full enforcement, so the module's
/// preflight and wiring are exercised without needing kernel support.
struct Recording {
    suitable: bool,
    available: bool,
    name: &'static str,
    seen: Mutex<Vec<Jail>>,
}
impl Recording {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            suitable: true,
            available: true,
            name: "recording",
            seen: Mutex::new(Vec::new()),
        })
    }
}
impl JailBackend for Recording {
    fn name(&self) -> &'static str {
        self.name
    }
    fn is_available(&self) -> bool {
        self.available
    }
    fn isolation(&self) -> tinybox_core::IsolationLevel {
        tinybox_core::IsolationLevel::Kernel
    }
    fn is_suitable_for_untrusted_code(&self) -> bool {
        self.suitable
    }
    fn is_suitable_for_untrusted_jail(&self, _: &Jail) -> bool {
        self.suitable
    }
    fn constraint_support(&self) -> tinybox_core::ConstraintSupport {
        use tinybox_core::{Constraint, ConstraintSupport, Enforcement};
        ConstraintSupport::NONE
            .with(Constraint::Filesystem, Enforcement::Enforced)
            .with(Constraint::Network, Enforcement::Enforced)
            .with(Constraint::Subprocess, Enforcement::Enforced)
    }
    fn spawn(
        &self,
        jail: &Jail,
        mut cmd: std::process::Command,
    ) -> std::io::Result<std::process::Child> {
        self.seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(jail.clone());
        cmd.spawn()
    }
}

fn jail_config() -> tinybox_bus::NativeJailConfig {
    tinybox_bus::NativeJailConfig {
        read_only: Vec::new(),
        read_write: Vec::new(),
        unix_paths: tinybox_bus::UnixPathGrants::default(),
        allow_net: true,
        allow_subprocess: true,
        enforcement: tinybox_bus::JailEnforcement::Enforced,
        require_process_isolation: true,
        deny_read: Vec::new(),
        resources: None,
    }
}

async fn local_resource(resources: &Resources) -> Result<ResourceId> {
    let resource = resources.reserve(ReserveRequest::Resource).await?;
    resources
        .create(CreateRequest {
            resource: resource.clone(),
            backend: "passthrough".into(),
            workspace: Workspace::Directory(".".into()),
            ..Default::default()
        })
        .await?;
    Ok(resource)
}

async fn start_request(
    resources: &Resources,
    resource: &ResourceId,
    argv: &[&str],
) -> Result<StdioStartRequest> {
    Ok(StdioStartRequest {
        process: resources
            .reserve(ReserveRequest::Process(resource.clone()))
            .await?,
        resource: resource.clone(),
        argv: argv.iter().map(|arg| (*arg).to_owned()).collect(),
        cwd: None,
        env: std::collections::BTreeMap::new(),
        jail: jail_config(),
    })
}

async fn start(
    resources: &Resources,
    resource: &ResourceId,
    backend: &Arc<Recording>,
    argv: &[&str],
) -> Result<ProcessRef> {
    let request = start_request(resources, resource, argv).await?;
    resources.start_stdio_with(request, backend.clone()).await
}

fn read(process: &ProcessRef, wait_ms: u64) -> StdioReadRequest {
    StdioReadRequest {
        process: process.clone(),
        max_bytes: 0,
        wait_ms,
    }
}

/// Keep reading until `done` accepts the accumulated output.
async fn collect(
    resources: &Resources,
    process: &ProcessRef,
    done: impl Fn(&[u8], &[u8], &tinybox_bus::StdioChunk) -> bool,
) -> Result<(Vec<u8>, Vec<u8>, tinybox_bus::StdioChunk)> {
    tokio::time::timeout(std::time::Duration::from_secs(20), async {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        loop {
            let chunk = resources.read_stdio(read(process, 200)).await?;
            out.extend_from_slice(&chunk.stdout);
            err.extend_from_slice(&chunk.stderr);
            if done(&out, &err, &chunk) {
                return Ok((out, err, chunk));
            }
        }
    })
    .await
    .map_err(|_| tinybus::Error::failed("stdio fixture timed out"))?
}

fn failed_with(result: Result<impl std::fmt::Debug>, name: &str) -> bool {
    matches!(result, Err(Error::MethodFailed { name: found, .. }) if found == name)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bytes_round_trip_through_stdin_and_stdout_until_eof() -> Result<()> {
    let resources = Resources::test_resources();
    let resource = local_resource(&resources).await?;
    let backend = Recording::new();
    let process = start(&resources, &resource, &backend, &["cat"]).await?;
    resources
        .write_stdio(StdioWriteRequest {
            process: process.clone(),
            data: b"hello\n".to_vec(),
        })
        .await?;
    let (out, _, _) = collect(&resources, &process, |out, _, _| out.ends_with(b"hello\n")).await?;
    assert_eq!(out, b"hello\n");
    assert!(resources.stdio_status(&process)?.running);
    resources.close_stdin(&process).await?;
    let (_, _, last) = collect(&resources, &process, |_, _, chunk| chunk.stdout_closed).await?;
    assert!(last.stderr_closed || last.status.exit.is_some() || !last.status.running);
    let status = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let status = resources.stdio_status(&process)?;
            if !status.running {
                return Ok::<_, Error>(status);
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .map_err(|_| Error::failed("child did not exit after stdin closed"))??;
    assert_eq!(status.exit, Some(StdioExit::Code(0)));
    assert!(failed_with(
        resources
            .write_stdio(StdioWriteRequest {
                process: process.clone(),
                data: b"late".to_vec(),
            })
            .await,
        STDIO_CLOSED
    ));
    resources.kill_stdio(&process).await?;
    resources.close(&resource).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stderr_stays_separate_and_exit_code_is_reported() -> Result<()> {
    let resources = Resources::test_resources();
    let resource = local_resource(&resources).await?;
    let backend = Recording::new();
    let process = start(
        &resources,
        &resource,
        &backend,
        &["sh", "-c", "echo out; echo err >&2; exit 3"],
    )
    .await?;
    let (out, err, last) = collect(&resources, &process, |_, _, chunk| {
        chunk.stdout_closed && chunk.stderr_closed && !chunk.status.running
    })
    .await?;
    assert_eq!(out, b"out\n");
    assert_eq!(err, b"err\n");
    assert_eq!(last.status.exit, Some(StdioExit::Code(3)));
    resources.close(&resource).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_full_buffer_backpressures_the_child_without_losing_bytes() -> Result<()> {
    let resources = Resources::test_resources();
    let resource = local_resource(&resources).await?;
    let backend = Recording::new();
    let total = tinybox_bus::MAX_STDIO_BUFFER_BYTES * 2 + 12_345;
    let script = format!("head -c {total} /dev/zero");
    let process = start(&resources, &resource, &backend, &["sh", "-c", &script]).await?;
    // Let the pump hit the buffer cap before anything is read.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let (out, _, _) = collect(&resources, &process, |_, _, chunk| chunk.stdout_closed).await?;
    assert_eq!(out.len(), total);
    resources.close(&resource).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn request_environment_applies_but_module_environment_does_not_leak() -> Result<()> {
    assert!(std::env::var_os("CARGO_MANIFEST_DIR").is_some());
    let resources = Resources::test_resources();
    let resource = local_resource(&resources).await?;
    let backend = Recording::new();
    let mut request = start_request(
        &resources,
        &resource,
        &["sh", "-c", "echo \"[$FROM_REQUEST][$CARGO_MANIFEST_DIR]\""],
    )
    .await?;
    request.env.insert("FROM_REQUEST".into(), "value".into());
    let process = resources.start_stdio_with(request, backend).await?;
    let (out, _, _) = collect(&resources, &process, |out, _, _| out.ends_with(b"\n")).await?;
    assert_eq!(out, b"[value][]\n");
    resources.close(&resource).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kill_ends_the_whole_process_group_and_releases_the_handle() -> Result<()> {
    let resources = Resources::test_resources();
    let resource = local_resource(&resources).await?;
    let backend = Recording::new();
    let process = start(
        &resources,
        &resource,
        &backend,
        &["sh", "-c", "sleep 60 & echo $!; wait"],
    )
    .await?;
    let (out, _, _) = collect(&resources, &process, |out, _, _| out.ends_with(b"\n")).await?;
    let grandchild = String::from_utf8_lossy(&out).trim().to_owned();
    assert!(alive(&grandchild));
    resources.kill_stdio(&process).await?;
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while alive(&grandchild) {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .map_err(|_| Error::failed("grandchild survived the kill"))?;
    assert!(failed_with(
        resources.stdio_status(&process),
        tinybox_bus::UNKNOWN_PROCESS
    ));
    // Kill is idempotent once released.
    resources.kill_stdio(&process).await?;
    resources.close(&resource).await
}

fn alive(pid: &str) -> bool {
    std::process::Command::new("kill")
        .args(["-0", pid])
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn closing_the_resource_kills_its_stdio_processes() -> Result<()> {
    let resources = Resources::test_resources();
    let resource = local_resource(&resources).await?;
    let backend = Recording::new();
    let process = start(&resources, &resource, &backend, &["sleep", "60"]).await?;
    assert!(resources.stdio_status(&process)?.running);
    resources.close(&resource).await?;
    assert!(failed_with(
        resources.stdio_status(&process),
        tinybox_bus::UNKNOWN_PROCESS
    ));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unsuitable_unavailable_and_noop_backends_refuse_before_admission() -> Result<()> {
    let resources = Resources::test_resources();
    let resource = local_resource(&resources).await?;
    let request = start_request(&resources, &resource, &["cat"]).await?;
    let unsuitable = Arc::new(Recording {
        suitable: false,
        available: true,
        name: "weak",
        seen: Mutex::new(Vec::new()),
    });
    let unavailable = Arc::new(Recording {
        suitable: true,
        available: false,
        name: "gone",
        seen: Mutex::new(Vec::new()),
    });
    let noop = Arc::new(Recording {
        suitable: true,
        available: true,
        name: tinybox_jail::NOOP_BACKEND_NAME,
        seen: Mutex::new(Vec::new()),
    });
    for backend in [unsuitable.clone(), unavailable.clone(), noop.clone()] {
        assert!(failed_with(
            resources
                .start_stdio_with(request.clone(), backend.clone())
                .await,
            tinybox_bus::UNSUPPORTED_OPERATION
        ));
        assert!(
            backend
                .seen
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_empty()
        );
    }
    // The refusals consumed nothing: the same reservation still starts.
    let process = resources
        .start_stdio_with(request, Recording::new())
        .await?;
    resources.kill_stdio(&process).await?;
    resources.close(&resource).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_jail_floor_and_credential_denials_reach_the_backend() -> Result<()> {
    let resources = Resources::test_resources();
    let resource = local_resource(&resources).await?;
    let backend = Recording::new();
    let secrets = tempfile::tempdir()?;
    let mut request = start_request(&resources, &resource, &["cat"]).await?;
    request.jail.allow_net = false;
    request.jail.allow_subprocess = false;
    request.jail.deny_read = vec![secrets.path().to_string_lossy().into_owned()];
    let process = resources.start_stdio_with(request, backend.clone()).await?;
    {
        let seen = backend
            .seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(seen.len(), 1);
        assert!(!seen[0].allow_net && !seen[0].allow_subprocess);
        assert_eq!(seen[0].deny_read, vec![secrets.path().canonicalize()?]);
    }
    resources.kill_stdio(&process).await?;
    resources.close(&resource).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_requests_replays_and_foreign_handles_are_rejected() -> Result<()> {
    let resources = Resources::test_resources();
    let resource = local_resource(&resources).await?;
    let other = local_resource(&resources).await?;
    let backend = Recording::new();

    let empty = start_request(&resources, &resource, &[]).await?;
    assert!(failed_with(
        resources.start_stdio_with(empty, backend.clone()).await,
        tinybox_bus::INVALID_STDIO
    ));
    let mut bad_env = start_request(&resources, &resource, &["cat"]).await?;
    bad_env.env.insert("A=B".into(), "x".into());
    assert!(failed_with(
        resources.start_stdio_with(bad_env, backend.clone()).await,
        tinybox_bus::INVALID_STDIO
    ));

    let request = start_request(&resources, &resource, &["cat"]).await?;
    let process = resources
        .start_stdio_with(request.clone(), backend.clone())
        .await?;
    // A delivery retry of the same request is idempotent.
    assert_eq!(
        resources
            .start_stdio_with(request.clone(), backend.clone())
            .await?,
        process
    );
    let mut changed = request;
    changed.argv = vec!["true".into()];
    assert!(failed_with(
        resources.start_stdio_with(changed, backend.clone()).await,
        tinybox_bus::INVALID_ID
    ));
    let foreign = ProcessRef {
        resource: other.clone(),
        process: process.process.clone(),
    };
    assert!(failed_with(
        resources.stdio_status(&foreign),
        tinybox_bus::INVALID_ID
    ));
    assert!(failed_with(
        resources
            .write_stdio(StdioWriteRequest {
                process: process.clone(),
                data: vec![0; tinybox_bus::MAX_STDIO_WRITE_BYTES + 1],
            })
            .await,
        tinybox_bus::RESOURCE_LIMIT
    ));
    let unreserved = StdioStartRequest {
        process: ResourceId("never-reserved".into()),
        resource: resource.clone(),
        argv: vec!["cat".into()],
        cwd: None,
        env: std::collections::BTreeMap::new(),
        jail: jail_config(),
    };
    assert!(failed_with(
        resources.start_stdio_with(unreserved, backend).await,
        tinybox_bus::DUPLICATE_ID
    ));
    resources.close(&resource).await?;
    resources.close(&other).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_stdio_processes_are_bounded() -> Result<()> {
    let resources = Resources::test_resources();
    let resource = local_resource(&resources).await?;
    let backend = Recording::new();
    let mut live = Vec::new();
    for _ in 0..tinybox_bus::MAX_STDIO_PROCESSES {
        live.push(start(&resources, &resource, &backend, &["cat"]).await?);
    }
    let extra = start_request(&resources, &resource, &["cat"]).await?;
    assert!(failed_with(
        resources.start_stdio_with(extra, backend).await,
        tinybox_bus::RESOURCE_LIMIT
    ));
    for process in live {
        resources.kill_stdio(&process).await?;
    }
    resources.close(&resource).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unknown_process_answers_unknown_and_kill_is_harmless() -> Result<()> {
    let resources = Resources::test_resources();
    let resource = local_resource(&resources).await?;
    let ghost = ProcessRef {
        resource: resource.clone(),
        process: ResourceId("ghost".into()),
    };
    assert!(failed_with(
        resources.read_stdio(read(&ghost, 0)).await,
        tinybox_bus::UNKNOWN_PROCESS
    ));
    assert!(failed_with(
        resources.close_stdin(&ghost).await,
        tinybox_bus::UNKNOWN_PROCESS
    ));
    assert!(failed_with(
        resources
            .write_stdio(StdioWriteRequest {
                process: ghost.clone(),
                data: b"x".to_vec(),
            })
            .await,
        tinybox_bus::UNKNOWN_PROCESS
    ));
    resources.kill_stdio(&ghost).await?;
    let missing = StdioStartRequest {
        process: ResourceId("p".into()),
        resource: ResourceId("no-such-resource".into()),
        argv: vec!["cat".into()],
        cwd: None,
        env: std::collections::BTreeMap::new(),
        jail: jail_config(),
    };
    assert!(failed_with(
        resources.start_stdio(missing).await,
        tinybox_bus::UNKNOWN_RESOURCE
    ));
    resources.close(&resource).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_program_that_cannot_start_fails_and_frees_its_slot() -> Result<()> {
    let resources = Resources::test_resources();
    let resource = local_resource(&resources).await?;
    let backend = Recording::new();
    let request = start_request(&resources, &resource, &["/nonexistent/tinybox-program"]).await?;
    assert!(failed_with(
        resources
            .start_stdio_with(request.clone(), backend.clone())
            .await,
        tinybox_bus::BACKEND_ERROR
    ));
    assert!(failed_with(
        resources.stdio_status(&ProcessRef {
            resource: resource.clone(),
            process: request.process.clone(),
        }),
        tinybox_bus::UNKNOWN_PROCESS
    ));
    resources.close(&resource).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reads_are_capped_and_an_idle_read_returns_empty_after_its_wait() -> Result<()> {
    let resources = Resources::test_resources();
    let resource = local_resource(&resources).await?;
    let backend = Recording::new();
    let process = start(&resources, &resource, &backend, &["cat"]).await?;
    let idle = resources.read_stdio(read(&process, 50)).await?;
    assert!(idle.stdout.is_empty() && idle.stderr.is_empty() && idle.status.running);
    resources
        .write_stdio(StdioWriteRequest {
            process: process.clone(),
            data: vec![b'a'; 100],
        })
        .await?;
    let mut taken = 0;
    while taken < 100 {
        let chunk = resources
            .read_stdio(StdioReadRequest {
                process: process.clone(),
                max_bytes: 10,
                wait_ms: 1_000,
            })
            .await?;
        assert!(chunk.stdout.len() <= 10);
        taken += chunk.stdout.len();
    }
    resources.kill_stdio(&process).await?;
    resources.close(&resource).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropping_the_registry_kills_a_stdio_child_it_still_owns() -> Result<()> {
    let resources = Resources::test_resources();
    let resource = local_resource(&resources).await?;
    let backend = Recording::new();
    let process = start(
        &resources,
        &resource,
        &backend,
        &["sh", "-c", "echo $$; exec sleep 60"],
    )
    .await?;
    let (out, _, _) = collect(&resources, &process, |out, _, _| out.ends_with(b"\n")).await?;
    let pid = String::from_utf8_lossy(&out).trim().to_owned();
    assert!(alive(&pid));
    drop(resources);
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while alive(&pid) {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .map_err(|_| Error::failed("child survived the registry"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_start_still_in_progress_blocks_lookups_and_duplicate_starts() -> Result<()> {
    let resources = Resources::test_resources();
    let resource = local_resource(&resources).await?;
    let backend = Recording::new();
    let request = start_request(&resources, &resource, &["cat"]).await?;
    let target = ProcessRef {
        resource: resource.clone(),
        process: request.process.clone(),
    };
    resources
        .stdio
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(target.process.clone(), StdioSlot::Starting(target.clone()));
    assert!(failed_with(
        resources.stdio_status(&target),
        tinybox_bus::DUPLICATE_ID
    ));
    assert!(failed_with(
        resources.start_stdio_with(request, backend).await,
        tinybox_bus::DUPLICATE_ID
    ));
    resources.remove_stdio(&target);
    resources.close(&resource).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn close_waits_for_a_start_in_flight_before_it_finishes() -> Result<()> {
    let resources = Arc::new(Resources::test_resources());
    let resource = local_resource(&resources).await?;
    let target = ProcessRef {
        resource: resource.clone(),
        process: ResourceId("starting".into()),
    };
    resources
        .stdio
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(target.process.clone(), StdioSlot::Starting(target.clone()));
    let closing = tokio::spawn({
        let (resources, resource) = (resources.clone(), resource.clone());
        async move { resources.close_stdio(&resource).await }
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert!(!closing.is_finished(), "close must wait for the start");
    // The start ends (failed or cancelled): its slot goes and Close finishes.
    resources.remove_stdio(&target);
    tokio::time::timeout(std::time::Duration::from_secs(5), closing)
        .await
        .map_err(|_| Error::failed("close did not finish after the start ended"))?
        .map_err(|error| Error::failed(error.to_string()))??;
    resources.close(&resource).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_stdio_cleanup_keeps_the_resource_registered_for_a_retry() -> Result<()> {
    let resources = Resources::test_resources();
    let resource = local_resource(&resources).await?;
    let target = ProcessRef {
        resource: resource.clone(),
        process: ResourceId("stuck".into()),
    };
    resources
        .stdio
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(
            target.process.clone(),
            StdioSlot::Ready(
                target.clone(),
                crate::tinybus_module::stdio::tests::inert_session(),
            ),
        );
    assert!(resources.close(&resource).await.is_err());
    // Still registered, so the next Close reaches the stuck child again.
    resources.inspect(&resource).await?;
    assert_eq!(resources.stdio_count(&resource), 1);
    resources.remove_stdio(&target);
    resources.close(&resource).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stdio_children_count_against_the_per_resource_process_limit() -> Result<()> {
    let resources = Resources::test_resources();
    let resource = local_resource(&resources).await?;
    let backend = Recording::new();
    let mut live = Vec::new();
    for _ in 0..tinybox_bus::MAX_STDIO_PROCESSES {
        live.push(start(&resources, &resource, &backend, &["cat"]).await?);
    }
    let mut detached = 0;
    loop {
        let process = resources
            .reserve(ReserveRequest::Process(resource.clone()))
            .await?;
        let spawned = resources
            .spawn(tinybox_bus::SpawnRequest {
                process,
                command: tinybox_bus::ExecRequest {
                    resource: resource.clone(),
                    argv: vec!["sleep".into(), "60".into()],
                    cwd: None,
                    env: std::collections::BTreeMap::new(),
                    stdin: None,
                },
            })
            .await;
        match spawned {
            Ok(_) => detached += 1,
            Err(_) => break,
        }
        assert!(
            detached <= tinybox_bus::MAX_PROCESSES_PER_RESOURCE,
            "unbounded"
        );
    }
    assert_eq!(
        detached + tinybox_bus::MAX_STDIO_PROCESSES,
        tinybox_bus::MAX_PROCESSES_PER_RESOURCE
    );
    for process in live {
        resources.kill_stdio(&process).await?;
    }
    resources.close(&resource).await
}
