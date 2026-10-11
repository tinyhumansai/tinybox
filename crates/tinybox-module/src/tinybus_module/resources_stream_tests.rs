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
        journal,
        task: Mutex::new(Some(task)),
        collector: Arc::new(tinybox_host::LimitedLocalHost::new(64)),
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
