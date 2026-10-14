//! Admission and cleanup for module-owned live executions.
use super::*;
use tinybox_bus::{CreateRequest, ExecRequest, ExecutionState, Workspace};

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
async fn request(
    resources: &Resources,
    resource: &ResourceId,
    argv: Vec<String>,
) -> Result<SpawnRequest> {
    Ok(SpawnRequest {
        process: resources
            .reserve(ReserveRequest::Process(resource.clone()))
            .await?,
        command: ExecRequest {
            resource: resource.clone(),
            argv,
            cwd: None,
            env: std::collections::BTreeMap::new(),
            stdin: None,
        },
    })
}
fn true_command() -> Vec<String> {
    #[cfg(windows)]
    return vec!["cmd".into(), "/C".into(), "exit 0".into()];
    #[cfg(not(windows))]
    vec!["/bin/true".into()]
}
async fn completed(resources: &Resources, process: &ProcessRef) -> Result<()> {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if resources.read_output(process, 0).await?.state != ExecutionState::Running {
                return Ok(());
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| tinybus::Error::failed("native fixture did not complete"))?
}

#[tokio::test]
async fn live_admission_is_bounded_until_outputs_are_explicitly_released() -> Result<()> {
    let resources = Resources::default();
    let resource = local_resource(&resources).await?;
    let mut processes = Vec::new();
    for _ in 0..MAX_STREAM_EXECUTIONS {
        let request = request(&resources, &resource, true_command()).await?;
        processes.push(resources.start_exec(request).await?);
    }
    let pending = request(&resources, &resource, true_command()).await?;
    assert!(resources.start_exec(pending.clone()).await.is_err());
    for process in processes {
        completed(&resources, &process).await?;
        resources.release_output(&process).await?;
    }
    let process = resources.start_exec(pending).await?;
    completed(&resources, &process).await?;
    resources.release_output(&process).await?;
    resources.release_output(&process).await?;
    resources.close(&resource).await?;
    Ok(())
}

#[tokio::test]
async fn stream_replay_keeps_request_identity_and_rejects_cross_resource_handles() -> Result<()> {
    let resources = Resources::default();
    let resource = local_resource(&resources).await?;
    let other = local_resource(&resources).await?;
    let request = request(&resources, &resource, true_command()).await?;
    let process = resources.start_exec(request.clone()).await?;
    assert_eq!(process, resources.start_exec(request.clone()).await?);
    let mut wrong = request;
    wrong.command.env.insert("DIFFERENT".into(), "1".into());
    assert!(resources.start_exec(wrong).await.is_err());
    let wrong = ProcessRef {
        resource: other.clone(),
        process: process.process.clone(),
    };
    assert!(resources.read_output(&wrong, 0).await.is_err());
    assert!(resources.cancel(&wrong).await.is_err());
    assert!(resources.release_output(&wrong).await.is_err());
    assert!(resources.read_output(&process, u64::MAX).await.is_err());
    completed(&resources, &process).await?;
    assert!(!resources.is_running(&process).await?);
    resources.release_output(&process).await?;
    assert!(resources.read_output(&process, 0).await.is_err());
    resources.close(&resource).await?;
    resources.close(&other).await?;
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn close_acknowledges_active_stream_cleanup_and_retires_its_output() -> Result<()> {
    let resources = Resources::default();
    let resource = local_resource(&resources).await?;
    let request = request(
        &resources,
        &resource,
        vec![
            "/bin/sh".into(),
            "-c".into(),
            "printf ready; exec sleep 600".into(),
        ],
    )
    .await?;
    let process = resources.start_exec(request.clone()).await?;
    assert!(resources.release_output(&process).await.is_err());
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        resources.close(&resource),
    )
    .await
    .map_err(|_| tinybus::Error::failed("Close did not acknowledge native cleanup"))??;
    assert!(resources.stream(&process)?.is_none());
    assert!(resources.start_exec(request).await.is_err());
    resources.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn rejected_start_keeps_its_reservation_and_provider_failures_use_safe_codes() -> Result<()> {
    let resources = Resources::default();
    let resource = local_resource(&resources).await?;
    let mut empty = request(&resources, &resource, Vec::new()).await?;
    assert!(resources.start_exec(empty.clone()).await.is_err());
    empty.command.argv = vec!["NONEXISTENT_CANARY_PRIVATE_PROGRAM_393932".into()];
    let process = resources.start_exec(empty).await?;
    completed(&resources, &process).await?;
    let batch = resources.read_output(&process, 0).await?;
    assert_eq!(
        batch.state,
        ExecutionState::Failed {
            code: ExecutionFailure::BackendFailed
        }
    );
    assert!(!format!("{:?}", batch.state).contains("CANARY"));
    resources.release_output(&process).await?;
    resources.close(&resource).await?;
    Ok(())
}

#[tokio::test]
async fn an_unowned_collector_or_unsupported_platform_refuses_live_execution() -> Result<()> {
    for platform in [
        crate::tinybus_module::Platform::current(),
        crate::tinybus_module::Platform::Other,
    ] {
        let resources = Resources::default();
        let resource = resources.reserve(ReserveRequest::Resource).await?;
        resources
            .create_on_for_platform(
                CreateRequest {
                    resource: resource.clone(),
                    backend: "passthrough".into(),
                    workspace: Workspace::Directory(".".into()),
                    ..Default::default()
                },
                Arc::new(tinybox_host::LocalHost::new()),
                platform,
            )
            .await?;
        let command = request(&resources, &resource, true_command()).await?;
        assert!(resources.start_exec(command).await.is_err());
        resources.close(&resource).await?;
    }
    Ok(())
}

#[tokio::test]
#[allow(
    clippy::panic,
    reason = "exercise acknowledged ownership after an unexpected execution task panic"
)]
async fn a_panicked_job_is_joined_and_cleanup_failure_stays_owned_until_retry() -> Result<()> {
    let resource = ResourceId("fixture-resource".into());
    let journal = Arc::new(OutputJournal::default());
    let guard = CompletionGuard(journal.clone());
    drop(guard);
    assert!(!journal.cleanup_acknowledged());
    let task = tokio::spawn(async {
        panic!("execution fixture panicked");
    });
    let stream = StreamExecution {
        request: SpawnRequest {
            process: ResourceId("fixture-process".into()),
            command: ExecRequest {
                resource,
                argv: true_command(),
                cwd: None,
                env: std::collections::BTreeMap::new(),
                stdin: None,
            },
        },
        jail: None,
        shell: None,
        platform_shell: None,
        timed_out: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        journal,
        task: Mutex::new(Some(task)),
        collector: Collector::Host(Arc::new(tinybox_host::LimitedLocalHost::new(64)), None),
    };
    assert!(stream.running());
    stream.stop().await?;
    assert!(stream.cleanup_acknowledged());
    assert!(!stream.running());
    stream.stop().await?;
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn exceeding_live_output_budget_stops_the_child_and_reports_a_safe_terminal_code()
-> Result<()> {
    let resources = Resources::default();
    let resource = local_resource(&resources).await?;
    let request = request(&resources, &resource, vec!["/bin/sh".into(), "-c".into(), "while :; do printf 012345678901234567890123456789012345678901234567890123456789012345; done".into()]).await?;
    let process = resources.start_exec(request).await?;
    completed(&resources, &process).await?;
    let batch = resources.read_output(&process, 0).await?;
    assert_eq!(
        batch.state,
        ExecutionState::Failed {
            code: ExecutionFailure::OutputLimit
        }
    );
    resources.release_output(&process).await?;
    resources.close(&resource).await?;
    Ok(())
}

#[tokio::test]
async fn concurrent_lost_reply_retries_reuse_the_same_execution_instead_of_consuming_twice()
-> Result<()> {
    use std::future::{Future, poll_fn};
    use std::task::Poll;
    let resources = Resources::default();
    let resource = local_resource(&resources).await?;
    let request = request(&resources, &resource, true_command()).await?;
    let slot = resources.slot(&resource).await?;
    let slot_guard = slot.lock().await;
    let mut first = Box::pin(resources.start_exec(request.clone()));
    let mut retry = Box::pin(resources.start_exec(request.clone()));
    let mut changed = request;
    changed.command.env.insert("DIFFERENT".into(), "1".into());
    let mut wrong_retry = Box::pin(resources.start_exec(changed));
    poll_fn(|cx| {
        assert!(first.as_mut().poll(cx).is_pending());
        assert!(retry.as_mut().poll(cx).is_pending());
        assert!(wrong_retry.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    drop(slot_guard);
    let (first, retry, wrong_retry) = tokio::join!(first, retry, wrong_retry);
    assert!(wrong_retry.is_err());
    let first = first?;
    assert_eq!(first, retry?);
    completed(&resources, &first).await?;
    resources.release_output(&first).await?;
    resources.close(&resource).await?;
    Ok(())
}

#[tokio::test]
async fn jailed_start_rejects_missing_grants_without_consuming_reservation() -> Result<()> {
    let resources = Resources::default();
    let resource = local_resource(&resources).await?;
    let pending = request(&resources, &resource, true_command()).await?;
    let config = tinybox_bus::NativeJailConfig {
        read_only: vec!["/tinybox-nonexistent-grant-fixture".into()],
        read_write: vec![],
        unix_paths: tinybox_bus::UnixPathGrants::default(),
        allow_net: true,
        allow_subprocess: true,
        enforcement: tinybox_bus::JailEnforcement::Declared,
        require_process_isolation: false,
    };
    assert!(
        resources
            .start_jailed_exec(pending.clone(), config)
            .await
            .is_err()
    );
    let process = resources.start_exec(pending).await?;
    completed(&resources, &process).await?;
    resources.close(&resource).await
}

#[derive(Debug)]
struct RemoteObservedFixture {
    pending: std::sync::atomic::AtomicBool,
    reject_retry: std::sync::atomic::AtomicBool,
    collected_calls: std::sync::atomic::AtomicUsize,
    wait_for_timeout: bool,
}
#[async_trait::async_trait]
impl tinybox_core::Host for RemoteObservedFixture {
    fn name(&self) -> &'static str {
        "ssh"
    }
    async fn run(
        &self,
        _: &tinybox_core::ExecRequest,
    ) -> tinybox_core::Result<tinybox_core::ExecOutput> {
        self.collected_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Err(tinybox_core::Error::UnsupportedStreaming {
            provider: "fixture".into(),
        })
    }
    async fn run_observed(
        &self,
        _: &tinybox_core::ExecRequest,
        observer: Arc<dyn tinybox_core::ExecutionObserver>,
    ) -> tinybox_core::Result<tinybox_core::ExecOutput> {
        observer.output(tinybox_core::OutputStream::Stdout, &[255, 0])?;
        self.pending
            .store(true, std::sync::atomic::Ordering::SeqCst);
        if self.wait_for_timeout {
            std::future::pending::<()>().await;
        }
        Err(tinybox_core::Error::ObservedCleanupPending {
            provider: "fixture".into(),
        })
    }
    fn has_pending_observed_cleanup(&self) -> bool {
        self.pending.load(std::sync::atomic::Ordering::SeqCst)
    }
    async fn retry_observed_cleanup(&self) -> tinybox_core::Result<()> {
        if self.reject_retry.load(std::sync::atomic::Ordering::SeqCst) {
            Err(tinybox_core::Error::ObservedCleanupPending {
                provider: "fixture".into(),
            })
        } else {
            self.pending
                .store(false, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
    }
}
#[tokio::test]
async fn remote_cleanup_failure_keeps_binary_output_and_owner_until_retry_ack() -> Result<()> {
    let host = Arc::new(RemoteObservedFixture {
        pending: std::sync::atomic::AtomicBool::new(false),
        reject_retry: std::sync::atomic::AtomicBool::new(true),
        collected_calls: std::sync::atomic::AtomicUsize::new(0),
        wait_for_timeout: false,
    });
    let resource = ResourceId("fixture-resource".into());
    let command = tinybox_core::ExecRequest::new(["fixture"]);
    let stream = StreamExecution::start(
        SpawnRequest {
            process: ResourceId("fixture-process".into()),
            command: ExecRequest {
                resource,
                argv: vec!["fixture".into()],
                cwd: None,
                env: std::collections::BTreeMap::new(),
                stdin: None,
            },
        },
        command,
        Collector::Host(host.clone(), None),
        None,
        None,
        None,
    );
    assert!(stream.stop().await.is_err());
    assert!(stream.running());
    let batch = stream
        .journal
        .read(0)
        .map_err(|_| tinybus::Error::failed("fixture read failed"))?;
    assert_eq!(
        batch.state,
        ExecutionState::Failed {
            code: ExecutionFailure::CleanupFailed
        }
    );
    assert_eq!(batch.chunks[0].bytes, [255, 0]);
    host.reject_retry
        .store(false, std::sync::atomic::Ordering::SeqCst);
    stream.stop().await?;
    assert!(!stream.running());
    assert!(stream.cleanup_acknowledged());
    assert_eq!(
        host.collected_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    Ok(())
}

#[derive(Debug, Default)]
struct DockerFaultHost {
    names: std::sync::Mutex<std::collections::BTreeSet<String>>,
    destroys: std::sync::atomic::AtomicUsize,
    pending: std::sync::atomic::AtomicBool,
    reject_retry: std::sync::atomic::AtomicBool,
}
#[async_trait::async_trait]
impl tinybox_core::Host for DockerFaultHost {
    fn name(&self) -> &'static str {
        "fixture"
    }
    async fn run(
        &self,
        command: &tinybox_core::ExecRequest,
    ) -> tinybox_core::Result<tinybox_core::ExecOutput> {
        match command.argv.get(1).map(String::as_str) {
            Some("run") => {
                let name = command
                    .argv
                    .windows(2)
                    .find(|pair| pair[0] == "--name")
                    .ok_or_else(|| tinybox_core::Error::EmptyCommand {
                        sandbox: "fixture".into(),
                    })?[1]
                    .clone();
                if !self
                    .names
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .insert(name)
                {
                    return Err(tinybox_core::Error::Backend {
                        sandbox: "docker".into(),
                        operation: "create",
                        message: "container name already in use".into(),
                    });
                }
                Ok(tinybox_core::ExecOutput::new(
                    0,
                    b"created".to_vec(),
                    Vec::new(),
                ))
            }
            Some("inspect") => Ok(tinybox_core::ExecOutput::new(
                0,
                b"running".to_vec(),
                Vec::new(),
            )),
            Some("rm") => {
                self.destroys
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(tinybox_core::ExecOutput::new(0, Vec::new(), Vec::new()))
            }
            Some("exec")
                if command
                    .argv
                    .iter()
                    .any(|argument| argument == "tinybox-observed-reserve") =>
            {
                Ok(tinybox_core::ExecOutput::new(
                    0,
                    b"ready\n".to_vec(),
                    Vec::new(),
                ))
            }
            _ => Err(tinybox_core::Error::ObservedCleanupPending {
                provider: "fixture".into(),
            }),
        }
    }
    async fn run_observed(
        &self,
        _: &tinybox_core::ExecRequest,
        observer: Arc<dyn tinybox_core::ExecutionObserver>,
    ) -> tinybox_core::Result<tinybox_core::ExecOutput> {
        observer.output(tinybox_core::OutputStream::Stdout, b"owned")?;
        self.pending
            .store(true, std::sync::atomic::Ordering::SeqCst);
        Err(tinybox_core::Error::ObservedCleanupPending {
            provider: "fixture".into(),
        })
    }
    fn has_pending_observed_cleanup(&self) -> bool {
        self.pending.load(std::sync::atomic::Ordering::SeqCst)
    }
    async fn retry_observed_cleanup(&self) -> tinybox_core::Result<()> {
        if self.reject_retry.load(std::sync::atomic::Ordering::SeqCst) {
            Err(tinybox_core::Error::ObservedCleanupPending {
                provider: "fixture".into(),
            })
        } else {
            self.pending
                .store(false, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
    }
}
async fn mock_docker_resource(
    resources: &Resources,
    host: Arc<DockerFaultHost>,
) -> Result<ResourceId> {
    let resource = resources.reserve(ReserveRequest::Resource).await?;
    resources
        .create_on(
            CreateRequest {
                resource: resource.clone(),
                backend: "docker".into(),
                workspace: Workspace::Image("fixture".into()),
                ..Default::default()
            },
            host,
        )
        .await?;
    Ok(resource)
}
#[tokio::test]
async fn docker_resources_use_distinct_container_names() -> Result<()> {
    let resources = Resources::default();
    let host = Arc::new(DockerFaultHost::default());
    let first = mock_docker_resource(&resources, host.clone()).await?;
    let second = mock_docker_resource(&resources, host.clone()).await?;
    assert_eq!(
        host.names
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len(),
        2
    );
    resources.close(&first).await?;
    resources.close(&second).await?;
    Ok(())
}
#[tokio::test]
async fn confirmed_container_destroy_keeps_native_cleanup_retryable_without_destroying_twice()
-> Result<()> {
    let resources = Resources::default();
    let host = Arc::new(DockerFaultHost::default());
    host.reject_retry
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let resource = mock_docker_resource(&resources, host.clone()).await?;
    let request = request(&resources, &resource, vec!["fixture".into()]).await?;
    let process = ProcessRef {
        resource: resource.clone(),
        process: request.process.clone(),
    };
    let slot = resources.slot(&resource).await?;
    {
        let guard = slot.lock().await;
        let entry = guard
            .as_ref()
            .ok_or_else(|| Error::failed("fixture resource missing"))?;
        let sandbox = entry
            .docker_sandbox
            .as_ref()
            .ok_or_else(|| Error::failed("fixture Docker sandbox missing"))?
            .for_observed_host(host.clone());
        let execution = Arc::new(StreamExecution::start(
            request,
            tinybox_core::ExecRequest::new(["fixture"]),
            Collector::Sandbox(Arc::new(sandbox), entry.id.clone(), None),
            None,
            None,
            None,
        ));
        resources
            .streams
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(process.process.clone(), execution);
    }
    assert!(resources.cancel(&process).await.is_err());
    assert_eq!(host.destroys.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert!(resources.close(&resource).await.is_err());
    assert_eq!(host.destroys.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert!(resources.is_running(&process).await?);
    host.reject_retry
        .store(false, std::sync::atomic::Ordering::SeqCst);
    resources.close(&resource).await?;
    assert_eq!(host.destroys.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert!(resources.stream(&process)?.is_none());
    assert!(resources.slot(&resource).await.is_err());
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn collector_drain_joins_its_owned_active_native_supervisor() -> Result<()> {
    use std::future::Future;
    use std::task::Poll;
    let resources = Resources::default();
    let resource = local_resource(&resources).await?;
    let request = request(
        &resources,
        &resource,
        vec![
            "/bin/sh".into(),
            "-c".into(),
            "printf ready; exec /bin/sleep 600".into(),
        ],
    )
    .await?;
    let process = resources.start_exec(request).await?;
    loop {
        if !resources.read_output(&process, 0).await?.chunks.is_empty() {
            break;
        }
        tokio::task::yield_now().await;
    }
    let stream = resources
        .stream(&process)?
        .ok_or_else(|| Error::failed("missing fixture stream"))?;
    let mut drain = Box::pin(stream.collector.drain());
    let completion =
        std::future::poll_fn(|context| Poll::Ready(drain.as_mut().poll(context))).await;
    drop(drain);
    resources.cancel(&process).await?;
    resources.release_output(&process).await?;
    resources.close(&resource).await?;
    assert!(
        matches!(completion, Poll::Pending),
        "collector drain must join its owned native supervisor"
    );
    Ok(())
}

async fn shell_request(
    resources: &Resources,
    resource: &ResourceId,
    state: &std::path::Path,
    payload: &str,
) -> Result<tinybox_bus::ShellExecRequest> {
    Ok(tinybox_bus::ShellExecRequest {
        process: resources
            .reserve(ReserveRequest::Process(resource.clone()))
            .await?,
        resource: resource.clone(),
        shell: tinybox_bus::SelectShellRequest {
            command: payload.into(),
            preserve_pipeline_status: false,
            runtime_path: None,
            python_utf8: false,
        },
        cwd: None,
        extra_env: std::collections::BTreeMap::default(),
        state_dir: state.to_string_lossy().into_owned(),
        timeout_ms: 5000,
        stdin: None,
        jail: None,
        hide_window: false,
    })
}
#[tokio::test]
async fn native_shell_replay_uses_original_request_and_retains_scratch_until_release()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let resources = Resources::default();
    let resource = local_resource(&resources).await?;
    let state = tempfile::tempdir()?;
    let request = shell_request(&resources, &resource, state.path(), "echo owned").await?;
    let process = resources.start_shell_exec(request.clone()).await?;
    assert_eq!(resources.start_shell_exec(request.clone()).await?, process);
    let mut changed = request;
    changed.timeout_ms += 1;
    assert!(resources.start_shell_exec(changed).await.is_err());
    completed(&resources, &process).await?;
    assert_eq!(
        resources.read_output(&process, 0).await?.state,
        ExecutionState::Exited { exit_code: 0 }
    );
    let scratch = state.path().join("artifacts/sandbox-scratch");
    assert_eq!(std::fs::read_dir(&scratch)?.count(), 1);
    resources.release_output(&process).await?;
    assert_eq!(std::fs::read_dir(&scratch)?.count(), 0);
    resources.close(&resource).await?;
    Ok(())
}
#[tokio::test]
async fn native_shell_invalid_budget_does_not_consume_its_reservation()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let resources = Resources::default();
    let resource = local_resource(&resources).await?;
    let state = tempfile::tempdir()?;
    let mut request = shell_request(&resources, &resource, state.path(), "echo accepted").await?;
    request.timeout_ms = 0;
    assert!(resources.start_shell_exec(request.clone()).await.is_err());
    request.timeout_ms = 5000;
    let process = resources.start_shell_exec(request).await?;
    completed(&resources, &process).await?;
    resources.release_output(&process).await?;
    resources.close(&resource).await?;
    Ok(())
}
#[tokio::test]
async fn native_shell_timeout_acknowledges_child_cleanup_before_output_release()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let resources = Resources::default();
    let resource = local_resource(&resources).await?;
    let state = tempfile::tempdir()?;
    #[cfg(unix)]
    let payload = "echo partial; sleep 60";
    #[cfg(windows)]
    let payload =
        "echo partial & powershell -NoProfile -NonInteractive -Command \"Start-Sleep -Seconds 60\"";
    let mut request = shell_request(&resources, &resource, state.path(), payload).await?;
    request.timeout_ms = 100;
    let process = resources.start_shell_exec(request).await?;
    completed(&resources, &process).await?;
    let output = resources.read_output(&process, 0).await?;
    assert_eq!(
        output.state,
        ExecutionState::Failed {
            code: ExecutionFailure::TimedOut
        }
    );
    assert_eq!(
        std::fs::read_dir(state.path().join("artifacts/sandbox-scratch"))?.count(),
        1
    );
    resources.release_output(&process).await?;
    resources.close(&resource).await?;
    Ok(())
}

#[tokio::test]
#[cfg(unix)]
async fn native_shell_clears_startup_hooks_after_approved_overrides_and_captures_binary_pipes()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let resources = Resources::default();
    let resource = local_resource(&resources).await?;
    let state = tempfile::tempdir()?;
    let startup = state.path().join("startup.sh");
    std::fs::write(&startup, "exit 77\n")?;
    let mut request = shell_request(
        &resources,
        &resource,
        state.path(),
        "cat; printf \\\\377 >&2; false; echo $APPROVED",
    )
    .await?;
    request
        .extra_env
        .insert("BASH_ENV".into(), startup.to_string_lossy().into_owned());
    request
        .extra_env
        .insert("SHELLOPTS".into(), "errexit".into());
    request.extra_env.insert("APPROVED".into(), "yes".into());
    request.stdin = Some(vec![0, 255, 1]);
    let process = resources.start_shell_exec(request).await?;
    completed(&resources, &process).await?;
    let output = resources.read_output(&process, 0).await?;
    assert_eq!(output.state, ExecutionState::Exited { exit_code: 0 });
    let stdout: Vec<u8> = output
        .chunks
        .iter()
        .filter(|c| c.stream == tinybox_bus::OutputStream::Stdout)
        .flat_map(|c| c.bytes.clone())
        .collect();
    assert_eq!(stdout, [0, 255, 1, b'y', b'e', b's', 10]);
    let stderr: Vec<u8> = output
        .chunks
        .iter()
        .filter(|c| c.stream == tinybox_bus::OutputStream::Stderr)
        .flat_map(|c| c.bytes.clone())
        .collect();
    assert_eq!(stderr, [255]);
    resources.release_output(&process).await?;
    resources.close(&resource).await?;
    Ok(())
}

#[tokio::test]
#[cfg(unix)]
async fn native_shell_output_limit_terminates_and_reaps_before_release()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let resources = Resources::default();
    let resource = local_resource(&resources).await?;
    let state = tempfile::tempdir()?;
    let request = shell_request(&resources, &resource, state.path(), "yes output").await?;
    let process = resources.start_shell_exec(request).await?;
    completed(&resources, &process).await?;
    let output = resources.read_output(&process, 0).await?;
    assert_eq!(
        output.state,
        ExecutionState::Failed {
            code: ExecutionFailure::OutputLimit
        }
    );
    resources.release_output(&process).await?;
    resources.close(&resource).await?;
    Ok(())
}

#[tokio::test]
async fn failed_scratch_deletion_keeps_output_and_close_retryable()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    for close in [false, true] {
        let resources = Resources::default();
        let resource = local_resource(&resources).await?;
        let state = tempfile::tempdir()?;
        let request = shell_request(&resources, &resource, state.path(), "echo owned").await?;
        let process = resources.start_shell_exec(request).await?;
        completed(&resources, &process).await?;
        let scratch = std::fs::read_dir(state.path().join("artifacts/sandbox-scratch"))?
            .next()
            .ok_or("missing scratch")??
            .path();
        let retained = scratch.with_extension("retained");
        std::fs::rename(&scratch, &retained)?;
        std::fs::write(&scratch, "blocks directory removal")?;
        assert!(resources.release_output(&process).await.is_err());
        assert!(resources.stream(&process)?.is_some());
        if close {
            assert!(resources.close(&resource).await.is_err());
            assert!(resources.stream(&process)?.is_some());
        }
        std::fs::remove_file(&scratch)?;
        std::fs::rename(&retained, &scratch)?;
        if !close {
            resources.release_output(&process).await?;
        }
        resources.close(&resource).await?;
        assert!(!scratch.exists());
        assert!(resources.stream(&process)?.is_none());
    }
    Ok(())
}

#[tokio::test]
async fn native_shell_refuses_nonlocal_or_nondirectory_collectors_before_admission()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let resources = Resources::default();
    let resource = local_resource(&resources).await?;
    let state = tempfile::tempdir()?;
    let shell = shell_request(&resources, &resource, state.path(), "echo owned").await?;
    let slot = resources.slot(&resource).await?;
    {
        let mut entry = slot.lock().await;
        let entry = entry.as_mut().ok_or("missing resource")?;
        entry.native_host = false;
    }
    let error = resources
        .start_shell_exec(shell.clone())
        .await
        .err()
        .ok_or("accepted nonlocal shell")?;
    assert_eq!(error.wire_name(), tinybox_bus::UNSUPPORTED_OPERATION);
    {
        let mut entry = slot.lock().await;
        let entry = entry.as_mut().ok_or("missing resource")?;
        entry.native_host = true;
        entry.workspace_root = None;
    }
    let error = resources
        .start_shell_exec(shell)
        .await
        .err()
        .ok_or("accepted nondirectory shell")?;
    assert_eq!(error.wire_name(), tinybox_bus::UNSUPPORTED_OPERATION);
    resources.close(&resource).await?;
    Ok(())
}

#[tokio::test]
async fn cancelled_native_shell_retains_scratch_until_output_release()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let resources = Resources::default();
    let resource = local_resource(&resources).await?;
    let state = tempfile::tempdir()?;
    #[cfg(unix)]
    let payload = "echo ready; sleep 60";
    #[cfg(windows)]
    let payload =
        "echo ready & powershell -NoProfile -NonInteractive -Command \"Start-Sleep -Seconds 60\"";
    let request = shell_request(&resources, &resource, state.path(), payload).await?;
    let process = resources.start_shell_exec(request).await?;
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while resources.read_output(&process, 0).await?.chunks.is_empty() {
            tokio::task::yield_now().await;
        }
        Ok::<_, tinybus::Error>(())
    })
    .await??;
    resources.cancel(&process).await?;
    assert_eq!(
        resources.read_output(&process, 0).await?.state,
        ExecutionState::Cancelled
    );
    let scratch = state.path().join("artifacts/sandbox-scratch");
    assert_eq!(std::fs::read_dir(&scratch)?.count(), 1);
    resources.release_output(&process).await?;
    assert_eq!(std::fs::read_dir(&scratch)?.count(), 0);
    resources.close(&resource).await?;
    Ok(())
}

#[tokio::test]
async fn native_shell_execution_preserves_admission_and_request_identity() -> Result<()> {
    let resources = Resources::default();
    let resource = local_resource(&resources).await?;
    let request = request(&resources, &resource, Vec::new()).await?;
    let shell = tinybox_bus::SelectShellRequest {
        command: "echo fixture".into(),
        preserve_pipeline_status: false,
        runtime_path: None,
        python_utf8: false,
    };
    let process = resources
        .start_platform_shell_exec(request.clone(), shell.clone())
        .await?;
    assert_eq!(
        process,
        resources
            .start_platform_shell_exec(request.clone(), shell.clone())
            .await?
    );
    let mut different = shell.clone();
    different.command = "echo different".into();
    assert!(
        resources
            .start_platform_shell_exec(request.clone(), different)
            .await
            .is_err()
    );
    assert!(resources.start_exec(request.clone()).await.is_err());
    completed(&resources, &process).await?;
    let batch = resources.read_output(&process, 0).await?;
    assert_eq!(batch.state, ExecutionState::Exited { exit_code: 0 });
    let bytes: Vec<_> = batch
        .chunks
        .iter()
        .flat_map(|chunk| chunk.bytes.iter().copied())
        .collect();
    assert_eq!(String::from_utf8_lossy(&bytes).trim(), "fixture");
    resources.release_output(&process).await?;
    let mut nonempty = request;
    nonempty.command.argv = true_command();
    assert!(
        resources
            .start_platform_shell_exec(nonempty, shell)
            .await
            .is_err()
    );
    resources.close(&resource).await?;
    Ok(())
}

#[tokio::test]
async fn shell_execution_rejects_remote_selection_without_consuming_admission() -> Result<()> {
    let resources = Resources::default();
    let resource = local_resource(&resources).await?;
    let request = request(&resources, &resource, Vec::new()).await?;
    let shell = tinybox_bus::SelectShellRequest {
        command: "echo fixture".into(),
        preserve_pipeline_status: false,
        runtime_path: None,
        python_utf8: false,
    };
    let slot = resources.slot(&resource).await?;
    {
        let mut guard = slot.lock().await;
        let entry = guard
            .as_mut()
            .ok_or_else(|| Error::failed("fixture resource missing"))?;
        entry.native_host = false;
    }
    assert!(
        matches!(resources.start_platform_shell_exec(request.clone(), shell.clone()).await,
        Err(tinybus::Error::MethodFailed { ref name, .. }) if name.as_str() == tinybox_bus::UNSUPPORTED_OPERATION)
    );
    {
        let mut guard = slot.lock().await;
        let entry = guard
            .as_mut()
            .ok_or_else(|| Error::failed("fixture resource missing"))?;
        entry.native_host = true;
    }
    let process = resources.start_platform_shell_exec(request, shell).await?;
    completed(&resources, &process).await?;
    resources.cancel(&process).await?;
    resources.release_output(&process).await?;
    resources.close(&resource).await?;
    Ok(())
}

#[tokio::test]
async fn timeout_status_survives_failed_cleanup_until_retry_acknowledges_it()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let resources = Resources::default();
    let resource = local_resource(&resources).await?;
    let state = tempfile::tempdir()?;
    let mut shell = shell_request(&resources, &resource, state.path(), "unused").await?;
    shell.timeout_ms = 1;
    let host = Arc::new(RemoteObservedFixture {
        pending: std::sync::atomic::AtomicBool::new(false),
        reject_retry: std::sync::atomic::AtomicBool::new(true),
        collected_calls: std::sync::atomic::AtomicUsize::new(0),
        wait_for_timeout: true,
    });
    let stream = StreamExecution::start(
        request(&resources, &resource, true_command()).await?,
        tinybox_core::ExecRequest::new(["unused"]),
        Collector::Host(host.clone(), None),
        None,
        Some(shell),
        None,
    );
    {
        let mut task = stream.task.lock().await;
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            task.as_mut().ok_or("missing execution task")?,
        )
        .await??;
        task.take();
    }
    assert!(stream.stop().await.is_err());
    assert_eq!(
        stream.journal.read(0)?.state,
        ExecutionState::Failed {
            code: ExecutionFailure::CleanupFailed,
        }
    );
    assert!(!stream.cleanup_acknowledged());
    host.reject_retry
        .store(false, std::sync::atomic::Ordering::SeqCst);
    stream.stop().await?;
    assert_eq!(
        stream.journal.read(0)?.state,
        ExecutionState::Failed {
            code: ExecutionFailure::TimedOut,
        }
    );
    assert!(stream.cleanup_acknowledged());
    resources.close(&resource).await?;
    Ok(())
}

#[tokio::test]
async fn close_during_shell_preparation_fences_admission_without_waiting_for_filesystem()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let resources = Arc::new(Resources::default());
    let resource = local_resource(&resources).await?;
    let state = tempfile::tempdir()?;
    let shell = shell_request(&resources, &resource, state.path(), "echo must-not-run").await?;
    let request = SpawnRequest {
        process: shell.process.clone(),
        command: ExecRequest {
            resource: resource.clone(),
            argv: vec!["shell".into()],
            cwd: None,
            env: std::collections::BTreeMap::default(),
            stdin: None,
        },
    };
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let started = entered.clone();
    let resume = release.clone();
    let prepared = Arc::new(std::sync::Mutex::new(None));
    let observed = prepared.clone();
    let owner = resources.clone();
    let pending = tokio::spawn(async move {
        owner
            .start_with_preparation(request, None, Some(shell), None, |preparation| async move {
                started.notify_one();
                resume.notified().await;
                let collector = preparation.finish().await?;
                *observed
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(collector.clone());
                Ok(collector)
            })
            .await
    });
    entered.notified().await;
    let closed = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        resources.close(&resource),
    )
    .await;
    release.notify_one();
    let result = pending.await?;
    assert!(
        closed.is_ok(),
        "Close waited for shell filesystem preparation"
    );
    closed??;
    assert!(
        prepared
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_some()
    );
    assert_eq!(
        std::fs::read_dir(state.path().join("artifacts/sandbox-scratch"))?.count(),
        0,
        "rejected preparation must explicitly dispose scratch while the context is still retained"
    );
    assert!(
        result.is_err(),
        "late preparation admitted execution after Close"
    );
    assert!(
        resources
            .streams
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_empty()
    );
    Ok(())
}

#[tokio::test]
async fn native_shell_replay_ignores_rediscovered_program()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let resources = Resources::default();
    let resource = local_resource(&resources).await?;
    let state = tempfile::tempdir()?;
    let shell = shell_request(&resources, &resource, state.path(), "echo replay").await?;
    let process = resources.start_shell_exec(shell.clone()).await?;
    let stream = resources.stream(&process)?.ok_or("missing stream")?;
    let mut rediscovered = stream.request.clone();
    rediscovered.command.argv = vec!["different-discovered-shell".into()];
    stream.check_replay(&rediscovered, None, Some(&shell), None)?;
    completed(&resources, &process).await?;
    resources.release_output(&process).await?;
    resources.close(&resource).await?;
    Ok(())
}

#[tokio::test]
async fn rejected_shell_scratch_cleanup_is_retained_for_close_and_shutdown_retry()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    for shutdown in [false, true] {
        let resources = Resources::default();
        let resource = local_resource(&resources).await?;
        let state = tempfile::tempdir()?;
        let shell = shell_request(&resources, &resource, state.path(), "echo must-not-run").await?;
        let request = SpawnRequest {
            process: shell.process.clone(),
            command: ExecRequest {
                resource: resource.clone(),
                argv: vec!["shell".into()],
                cwd: None,
                env: std::collections::BTreeMap::default(),
                stdin: None,
            },
        };
        let scratch = state.path().join("artifacts/sandbox-scratch");
        let result = resources
            .start_with_preparation(request, None, Some(shell), None, |preparation| async {
                let collector = preparation.finish().await?;
                resources.close(&resource).await?;
                if let Collector::Shell(shell) = &collector {
                    shell
                        .scratch_deletion_blocked
                        .store(true, std::sync::atomic::Ordering::SeqCst);
                }
                Ok(collector)
            })
            .await;
        assert_eq!(
            result.err().map(|error| error.wire_name().to_owned()),
            Some(tinybox_bus::BACKEND_ERROR.to_owned())
        );
        assert_eq!(resources.rejected_shells.lock().await.len(), 1);
        resources.rejected_shells.lock().await[0]
            .1
            .scratch_deletion_blocked
            .store(false, std::sync::atomic::Ordering::SeqCst);
        if shutdown {
            resources.shutdown().await?;
        } else {
            resources.close(&resource).await?;
        }
        assert!(resources.rejected_shells.lock().await.is_empty());
        assert_eq!(std::fs::read_dir(&scratch)?.count(), 0);
    }
    Ok(())
}

#[tokio::test]
async fn unreserved_shell_processes_are_rejected_before_preparation() -> Result<()> {
    let resources = Resources::default();
    let resource = local_resource(&resources).await?;
    let request = SpawnRequest {
        process: ResourceId("unreserved-process".into()),
        command: ExecRequest {
            resource: resource.clone(),
            argv: true_command(),
            cwd: None,
            env: std::collections::BTreeMap::default(),
            stdin: None,
        },
    };
    let called = std::sync::atomic::AtomicBool::new(false);
    let result = resources
        .start_with_preparation(request, None, None, None, |preparation| async {
            called.store(true, std::sync::atomic::Ordering::SeqCst);
            preparation.finish().await
        })
        .await;
    assert!(result.is_err());
    assert!(
        !called.load(std::sync::atomic::Ordering::SeqCst),
        "unreserved requests must not allocate scratch or run preflight"
    );
    resources.close(&resource).await?;
    Ok(())
}

#[tokio::test]
async fn rejected_scratch_failure_does_not_prevent_close_from_fencing_and_stopping_streams()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let resources = Resources::default();
    let resource = local_resource(&resources).await?;
    let state = tempfile::tempdir()?;
    let shell_request = shell_request(&resources, &resource, state.path(), "echo unused").await?;
    let context = super::super::super::native_shell::ShellContext::prepare(
        shell_request,
        state.path(),
        &tinybox_core::ExecRequest::new(["unused"]),
    )?;
    context
        .scratch_deletion_blocked
        .store(true, std::sync::atomic::Ordering::SeqCst);
    resources
        .rejected_shells
        .lock()
        .await
        .push((resource.clone(), context.clone()));
    let process = resources
        .start_exec(request(&resources, &resource, true_command()).await?)
        .await?;
    let stream = resources.stream(&process)?.ok_or("missing stream")?;
    assert!(resources.close(&resource).await.is_err());
    assert!(
        stream.cleanup_acknowledged(),
        "scratch failure must not bypass stream shutdown"
    );
    assert!(
        resources
            .reserve(ReserveRequest::Process(resource.clone()))
            .await
            .is_err(),
        "scratch failure must not leave the resource open"
    );
    context
        .scratch_deletion_blocked
        .store(false, std::sync::atomic::Ordering::SeqCst);
    resources.close(&resource).await?;
    Ok(())
}

#[tokio::test]
async fn concurrent_preparations_share_a_bounded_admission_budget()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let resources = Arc::new(Resources::default());
    let resource = local_resource(&resources).await?;
    let request = request(&resources, &resource, true_command()).await?;
    let (entered, mut receiver) = tokio::sync::mpsc::channel(1);
    let release = Arc::new(tokio::sync::Barrier::new(MAX_STREAM_EXECUTIONS + 1));
    let mut pending = Vec::new();
    for _ in 0..MAX_STREAM_EXECUTIONS {
        let owner = resources.clone();
        let request = request.clone();
        let entered = entered.clone();
        let release = release.clone();
        pending.push(tokio::spawn(async move {
            owner
                .start_with_preparation(request, None, None, None, |preparation| async move {
                    entered
                        .send(())
                        .await
                        .map_err(|error| Error::failed(error.to_string()))?;
                    release.wait().await;
                    preparation.finish().await
                })
                .await
        }));
        receiver.recv().await.ok_or("preparation did not start")?;
    }
    let called = std::sync::atomic::AtomicBool::new(false);
    let rejected = resources
        .start_with_preparation(request, None, None, None, |preparation| async {
            called.store(true, std::sync::atomic::Ordering::SeqCst);
            preparation.finish().await
        })
        .await;
    assert_eq!(
        rejected.err().map(|error| error.wire_name().to_owned()),
        Some(tinybox_bus::RESOURCE_LIMIT.to_owned())
    );
    assert!(!called.load(std::sync::atomic::Ordering::SeqCst));
    release.wait().await;
    for task in pending {
        task.await??;
    }
    resources.close(&resource).await?;
    assert_eq!(
        resources.preparations.available_permits(),
        MAX_STREAM_EXECUTIONS
    );
    Ok(())
}
