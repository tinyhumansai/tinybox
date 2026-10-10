//! Owned detached handles acknowledge cleanup and reclaim native tasks.
use super::*;

#[cfg(unix)]
#[tokio::test]
async fn cleanup_failures_are_retained_and_never_acknowledged_as_success() -> Result<()> {
    let task = tokio::spawn(async {
        Err(Error::Backend {
            sandbox: crate::LOCAL.into(),
            operation: "cleanup",
            message: "injected native failure".into(),
        })
    });
    let mut process = ManagedProcess {
        cancel: None,
        task: Some(task),
        terminal: Ok(()),
        cleanup_failed: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
        state: LimitedLocalHost::new(100).state,
        group: -1,
        supervisor_failed: true,
    };
    assert!(process.stop().await.is_err());
    assert!(process.stop().await.is_err());
    let task = tokio::spawn(std::future::pending::<Result<()>>());
    task.abort();
    let mut process = ManagedProcess {
        cancel: None,
        task: Some(task),
        terminal: Ok(()),
        cleanup_failed: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
        state: LimitedLocalHost::new(100).state,
        group: -1,
        supervisor_failed: true,
    };
    assert!(process.stop().await.is_err());
    let mut child = Command::new("true")
        .spawn()
        .map_err(|error| Error::io("spawn", &error))?;
    assert!(terminate(&mut child, -1).await.is_err());
    child
        .wait()
        .await
        .map_err(|error| Error::io("wait", &error))?;
    assert!(group(&child).is_err());
    assert!(
        cleanup_deadline(std::time::Duration::ZERO, std::future::pending())
            .await
            .is_err()
    );
    assert!(
        wait_group(1, std::time::Duration::ZERO, |_| Ok(true))
            .await
            .is_err()
    );
    assert!(
        wait_group(1, std::time::Duration::from_secs(5), |_| Err(
            Error::Backend {
                sandbox: crate::LOCAL.into(),
                operation: "observe group",
                message: "injected failure".into()
            }
        ))
        .await
        .is_err()
    );
    #[cfg(target_os = "linux")]
    assert!(group_alive(nix::unistd::getpgrp().as_raw())?);
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn detached_stop_and_drop_join_supervised_children() -> Result<()> {
    let host = LimitedLocalHost::new(100);
    let mut process = host.spawn(&ExecRequest::new(["sleep", "600"]))?;
    assert!(process.is_running());
    process.stop().await?;
    process.stop().await?;
    assert!(!process.is_running());
    let process = host.spawn(&ExecRequest::new(["sleep", "600"]))?;
    drop(process);
    host.drain().await;
    assert_eq!(host.state.active.load(Ordering::SeqCst), 0);
    let mut finished = host.spawn(&ExecRequest::new(["cat"]).with_stdin(b"input".to_vec()))?;
    host.drain().await;
    assert!(!finished.is_running());
    finished.stop().await?;
    assert!(host.spawn(&ExecRequest::new(Vec::<String>::new())).is_err());
    assert!(
        host.spawn(&ExecRequest::new(["/nonexistent/tinybox-program"]))
            .is_err()
    );
    Ok(())
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn stopping_a_shell_reaps_the_direct_child_and_terminates_its_descendant() -> Result<()> {
    let directory = tempfile::tempdir().map_err(|error| Error::io("tempdir", &error))?;
    let ready = directory.path().join("pids");
    let script = format!(
        "sleep 600 & echo $$ $! > {}; wait",
        tinybox_core::shell::quote(&ready.to_string_lossy())
    );
    let host = LimitedLocalHost::new(100);
    let mut process = host.spawn(&ExecRequest::new(["sh", "-c", &script]))?;
    let pids = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if let Ok(contents) = std::fs::read_to_string(&ready)
                && contents.split_whitespace().count() == 2
            {
                break contents;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|error| Error::Backend {
        sandbox: crate::LOCAL.into(),
        operation: "await readiness",
        message: error.to_string(),
    })?;
    process.stop().await?;
    for (index, pid) in pids.split_whitespace().enumerate() {
        let status = std::fs::read_to_string(format!("/proc/{pid}/status"));
        if index == 0 {
            assert!(status.is_err(), "direct child was not reaped");
        } else if let Ok(status) = status {
            assert!(
                status
                    .lines()
                    .find(|line| line.starts_with("State:"))
                    .is_some_and(|line| line.contains("Z (zombie)")),
                "descendant still executes after cleanup"
            );
        }
    }
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn retained_native_cleanup_failure_is_retried_by_managed_stop() -> Result<()> {
    let host = LimitedLocalHost::new(100);
    let mut command = crate::LocalHost::command(&ExecRequest::new(["sleep", "600"]))?;
    prepare(&mut command)?;
    let child = command
        .spawn()
        .map_err(|error| Error::io("fixture spawn", &error))?;
    let group = group(&child)?;
    let pid = child.id().ok_or_else(|| Error::Backend {
        sandbox: crate::LOCAL.into(),
        operation: "fixture pid",
        message: "missing".into(),
    })?;
    host.state
        .cleanup_failures
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(
            group,
            std::sync::Arc::new(tokio::sync::Mutex::new(Some(child))),
        );
    let mut process = ManagedProcess {
        cancel: None,
        task: None,
        terminal: Err("transient native error".into()),
        cleanup_failed: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
        state: host.state.clone(),
        group,
        supervisor_failed: false,
    };
    assert!(!process.is_cleaned());
    process.stop().await?;
    assert!(process.is_cleaned());
    process.stop().await?;
    #[cfg(target_os = "linux")]
    assert!(!std::path::Path::new(&format!("/proc/{pid}/status")).exists());
    Ok(())
}
