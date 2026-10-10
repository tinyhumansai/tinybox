//! Deterministic startup and cleanup races over an injected host.
use super::*;
use tinybox_core::{ExecOutput as NativeOutput, ExecRequest as NativeRequest, Host};

#[derive(Debug, Default)]
struct DelayedHost {
    started: tokio::sync::Notify,
    release: tokio::sync::Notify,
    destroyed: std::sync::atomic::AtomicBool,
    exec_started: tokio::sync::Notify,
    exec_release: tokio::sync::Notify,
    exec_finished: std::sync::atomic::AtomicBool,
}

#[async_trait::async_trait]
impl Host for DelayedHost {
    fn name(&self) -> &'static str {
        "local"
    }
    async fn run(&self, request: &NativeRequest) -> tinybox_core::Result<NativeOutput> {
        if request.argv.get(1).is_some_and(|arg| arg == "run") {
            self.started.notify_one();
            self.release.notified().await;
        }
        if request.argv.get(1).is_some_and(|arg| arg == "exec") {
            self.exec_started.notify_one();
            self.exec_release.notified().await;
            self.exec_finished
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
        if request.argv.get(1).is_some_and(|arg| arg == "rm") {
            self.destroyed
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
        let stdout = if request.argv.get(1).is_some_and(|arg| arg == "inspect") {
            b"running".to_vec()
        } else {
            Vec::new()
        };
        Ok(NativeOutput::new(0, stdout, Vec::new()))
    }
}

#[tokio::test]
async fn close_during_native_creation_destroys_the_eventual_resource() -> Result<()> {
    let resources = Arc::new(Resources::default());
    let host = Arc::new(DelayedHost::default());
    let id = ResourceId("delayed-create".into());
    let create_resources = resources.clone();
    let create_host = host.clone();
    let create_id = id.clone();
    let creating = tokio::spawn(async move {
        create_resources
            .create_on(
                CreateRequest {
                    resource: create_id,
                    backend: "docker".into(),
                    workspace: Workspace::Image("mock-image".into()),
                    env: BTreeMap::new(),
                },
                create_host,
            )
            .await
    });
    host.started.notified().await;
    let close_resources = resources.clone();
    let close_id = id.clone();
    let close_started = Arc::new(tokio::sync::Notify::new());
    let close_signal = close_started.clone();
    let closing = tokio::spawn(async move {
        close_signal.notify_one();
        close_resources.close(&close_id).await
    });
    close_started.notified().await;
    assert!(!closing.is_finished());
    assert!(!host.destroyed.load(std::sync::atomic::Ordering::SeqCst));
    host.release.notify_one();
    creating.await.map_err(Error::failed)??;
    closing.await.map_err(Error::failed)??;
    assert!(host.destroyed.load(std::sync::atomic::Ordering::SeqCst));
    assert!(resources.inspect(&id).await.is_err());
    Ok(())
}

#[tokio::test]
async fn close_cancels_owned_native_execution_after_its_waiter_drops() -> Result<()> {
    let resources = Arc::new(Resources::default());
    let host = Arc::new(DelayedHost::default());
    let id = ResourceId("dropped-exec".into());
    host.release.notify_one();
    resources
        .create_on(
            CreateRequest {
                resource: id.clone(),
                backend: "docker".into(),
                workspace: Workspace::Image("mock-image".into()),
                env: BTreeMap::new(),
            },
            host.clone(),
        )
        .await?;
    let exec_resources = resources.clone();
    let request = ExecRequest {
        resource: id.clone(),
        argv: vec!["mock-workload".into()],
        cwd: None,
        env: BTreeMap::new(),
        stdin: None,
    };
    let native = tokio::spawn(async move { exec_resources.exec(request).await });
    let waiter = tokio::spawn(super::super::finish_operation(native));
    host.exec_started.notified().await;
    waiter.abort();
    assert!(waiter.await.is_err());
    let close_resources = resources.clone();
    let close_id = id.clone();
    let close_started = Arc::new(tokio::sync::Notify::new());
    let close_signal = close_started.clone();
    let closing = tokio::spawn(async move {
        close_signal.notify_one();
        close_resources.close(&close_id).await
    });
    close_started.notified().await;
    assert!(!host.exec_finished.load(std::sync::atomic::Ordering::SeqCst));
    closing.await.map_err(Error::failed)??;
    assert!(!host.exec_finished.load(std::sync::atomic::Ordering::SeqCst));
    assert!(host.destroyed.load(std::sync::atomic::Ordering::SeqCst));
    assert!(resources.inspect(&id).await.is_err());
    Ok(())
}

#[tokio::test]
async fn admission_limits_bound_live_resources_and_tombstones() -> Result<()> {
    let mut issued = BTreeSet::new();
    for invalid in [
        String::new(),
        "has space".into(),
        "../path".into(),
        "a".repeat(tinybox_bus::MAX_ID_BYTES + 1),
    ] {
        assert!(reserve(&mut issued, &ResourceId(invalid)).is_err());
    }
    for index in 0..tinybox_bus::MAX_RESERVATIONS {
        reserve(&mut issued, &ResourceId(format!("reservation-{index}")))?;
    }
    assert!(reserve(&mut issued, &ResourceId("overflow".into())).is_err());
    retire(&mut issued, &ResourceId("reservation-0".into()))?;
    assert!(retire(&mut issued, &ResourceId("new-overflow".into())).is_err());
    let resources = Resources::default();
    for index in 0..tinybox_bus::MAX_ACTIVE_RESOURCES {
        resources
            .create(CreateRequest {
                resource: ResourceId(format!("live-{index}")),
                backend: "passthrough".into(),
                workspace: Workspace::Directory(".".into()),
                env: BTreeMap::new(),
            })
            .await?;
    }
    assert!(
        resources
            .create(CreateRequest {
                resource: ResourceId("live-overflow".into()),
                backend: "passthrough".into(),
                workspace: Workspace::Directory(".".into()),
                env: BTreeMap::new()
            })
            .await
            .is_err()
    );
    for index in 0..tinybox_bus::MAX_ACTIVE_RESOURCES {
        resources
            .close(&ResourceId(format!("live-{index}")))
            .await?;
    }
    Ok(())
}

#[tokio::test]
async fn a_pending_create_does_not_block_closing_another_resource() -> Result<()> {
    let resources = Arc::new(Resources::default());
    let ready = ResourceId("independent-ready".into());
    resources
        .create(CreateRequest {
            resource: ready.clone(),
            backend: "passthrough".into(),
            workspace: Workspace::Directory(".".into()),
            env: BTreeMap::new(),
        })
        .await?;
    let host = Arc::new(DelayedHost::default());
    let pending_resources = resources.clone();
    let pending_host = host.clone();
    let pending = tokio::spawn(async move {
        pending_resources
            .create_on(
                CreateRequest {
                    resource: ResourceId("pending-independent".into()),
                    backend: "docker".into(),
                    workspace: Workspace::Image("mock".into()),
                    env: BTreeMap::new(),
                },
                pending_host,
            )
            .await
    });
    host.started.notified().await;
    resources.close(&ready).await?;
    assert!(!pending.is_finished());
    host.release.notify_one();
    let created = pending.await.map_err(Error::failed)??;
    resources.close(&created.resource).await?;
    Ok(())
}

#[tokio::test]
async fn process_admission_refuses_overflow_before_native_start() -> Result<()> {
    let resources = Resources::default();
    let host = Arc::new(DelayedHost::default());
    host.release.notify_one();
    let id = ResourceId("full-processes".into());
    resources
        .create_on(
            CreateRequest {
                resource: id.clone(),
                backend: "docker".into(),
                workspace: Workspace::Image("mock".into()),
                env: BTreeMap::new(),
            },
            host,
        )
        .await?;
    let slot = resources.slot(&id).await?;
    {
        let mut slot = slot.lock().await;
        let entry = slot
            .as_mut()
            .ok_or_else(|| Error::failed("missing test resource"))?;
        for index in 0..tinybox_bus::MAX_PROCESSES_PER_RESOURCE {
            entry.processes.insert(
                ResourceId(format!("existing-{index}")),
                tinybox_core::detach::mint(),
            );
        }
    }
    assert!(
        resources
            .spawn(SpawnRequest {
                process: ResourceId("overflow-process".into()),
                command: ExecRequest {
                    resource: id,
                    argv: vec!["unused".into()],
                    cwd: None,
                    env: BTreeMap::new(),
                    stdin: None
                }
            })
            .await
            .is_err()
    );
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn close_reaps_a_running_native_exec_before_returning() -> Result<()> {
    let directory = tempfile::tempdir().map_err(Error::failed)?;
    let ready = directory.path().join("ready.pid");
    let resources = Arc::new(Resources::default());
    let id = ResourceId("native-close".into());
    resources
        .create(CreateRequest {
            resource: id.clone(),
            backend: "passthrough".into(),
            workspace: Workspace::Directory(".".into()),
            env: BTreeMap::new(),
        })
        .await?;
    let runner = resources.clone();
    let script = format!(
        "echo $$ > {}; exec sleep 600",
        tinybox_core::shell::quote(&ready.to_string_lossy())
    );
    let command = ExecRequest {
        resource: id.clone(),
        argv: vec!["sh".into(), "-c".into(), script],
        cwd: None,
        env: BTreeMap::new(),
        stdin: None,
    };
    let running = tokio::spawn(async move { runner.exec(command).await });
    let pid = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if let Ok(contents) = std::fs::read_to_string(&ready)
                && !contents.trim().is_empty()
            {
                return contents.trim().to_owned();
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(Error::failed)?;
    resources.close(&id).await?;
    assert!(running.await.map_err(Error::failed)?.is_err());
    let probe = tinybox_host::LocalHost::new()
        .run(&NativeRequest::new(["kill", "-0", &pid]))
        .await
        .map_err(|error| backend_error(&error))?;
    assert!(!probe.succeeded());
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn module_collection_enforces_output_cap_before_a_reply_is_allocated() -> Result<()> {
    let resources = Resources::default();
    let id = ResourceId("output-overflow".into());
    resources
        .create(CreateRequest {
            resource: id.clone(),
            backend: "passthrough".into(),
            workspace: Workspace::Directory(".".into()),
            env: BTreeMap::new(),
        })
        .await?;
    let error = resources
        .exec(ExecRequest {
            resource: id.clone(),
            argv: vec!["yes".into(), "output".into()],
            cwd: None,
            env: BTreeMap::new(),
            stdin: None,
        })
        .await
        .err()
        .ok_or_else(|| Error::failed("expected output limit error"))?;
    assert_eq!(error.wire_name(), tinybox_bus::OUTPUT_LIMIT);
    assert!(resources.inspect(&id).await.is_ok());
    resources.close(&id).await?;
    Ok(())
}
