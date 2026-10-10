//! Bounded collection, simultaneous draining, and supervisor cleanup.
use super::*;

#[cfg(target_os = "linux")]
#[tokio::test]
async fn overflow_terminates_inherited_pipe_descendants_before_drain_returns() -> Result<()> {
    let directory = tempfile::tempdir().map_err(|error| Error::io("tempdir", &error))?;
    let ready = directory.path().join("descendant.pid");
    let script = format!(
        "sleep 600 & echo $! > {}; yes",
        tinybox_core::shell::quote(&ready.to_string_lossy())
    );
    let host = LimitedLocalHost::new(16);
    assert!(matches!(
        host.run(&ExecRequest::new(["sh", "-c", &script])).await,
        Err(Error::OutputLimitExceeded { .. })
    ));
    host.drain().await;
    let pid = std::fs::read_to_string(&ready).map_err(|error| Error::io("read pid", &error))?;
    let status =
        std::fs::read_to_string(format!("/proc/{}/status", pid.trim())).unwrap_or_default();
    let alive = status
        .lines()
        .find(|line| line.starts_with("State:"))
        .is_some_and(|line| !line.contains("Z (zombie)"));
    if alive {
        let _ = LocalHost::new()
            .run(&ExecRequest::new(["kill", "-KILL", pid.trim()]))
            .await;
    }
    assert!(
        !alive,
        "output supervisor returned while descendant was alive: {status}"
    );
    Ok(())
}

#[tokio::test]
async fn combined_stream_budget_is_enforced_and_child_is_reaped() -> Result<()> {
    let host = LimitedLocalHost::new(100);
    for script in [
        "printf '%200s' x",
        "printf '%200s' x >&2",
        "printf '%60s' x; printf '%60s' x >&2",
        "yes output",
    ] {
        let result = host.run(&ExecRequest::new(["sh", "-c", script])).await;
        assert!(matches!(
            result,
            Err(Error::OutputLimitExceeded { limit: 100 })
        ));
        host.drain().await;
        assert_eq!(host.state.active.load(Ordering::SeqCst), 0);
    }
    Ok(())
}

#[tokio::test]
async fn both_pipes_and_large_stdin_are_drained_concurrently() -> Result<()> {
    let host = LimitedLocalHost::new(400_000);
    let payload = vec![b'x'; 150_000];
    let output = host
        .run(
            &ExecRequest::new(["sh", "-c", "cat; printf '%150000s' y >&2"])
                .with_stdin(payload.clone()),
        )
        .await?;
    assert_eq!(output.stdout, payload);
    assert_eq!(output.stderr.len(), 150_000);
    assert_eq!(output.exit_code, 0);
    assert_eq!(host.name(), crate::LOCAL);
    let address = ([127, 0, 0, 1], 1234).into();
    assert_eq!(host.forward(address).await?.local_addr(), address);
    Ok(())
}

#[tokio::test]
async fn empty_and_exact_budget_outputs_remain_successful() -> Result<()> {
    let empty = LimitedLocalHost::new(0)
        .run(&ExecRequest::new(["true"]))
        .await?;
    assert_eq!(empty.stdout.len(), 0);
    let host = LimitedLocalHost::new(3);
    let exact = host.run(&ExecRequest::new(["printf", "abc"])).await?;
    assert_eq!(exact.stdout, b"abc");
    let failure = host.run(&ExecRequest::new(["sh", "-c", "exit 7"])).await?;
    assert_eq!(failure.exit_code, 7);
    assert!(
        host.run(&ExecRequest::new(Vec::<String>::new()))
            .await
            .is_err()
    );
    assert!(
        host.run(&ExecRequest::new(["tinybox-nonexistent-program"]))
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn cancelled_caller_leaves_a_supervisor_that_drain_reaps() -> Result<()> {
    let host = LimitedLocalHost::new(100);
    let runner = host.clone();
    let running =
        tokio::spawn(async move { runner.run(&ExecRequest::new(["sleep", "600"])).await });
    while host.state.active.load(Ordering::SeqCst) == 0 {
        tokio::task::yield_now().await;
    }
    running.abort();
    assert!(running.await.is_err());
    host.drain().await;
    assert_eq!(host.state.active.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn failing_output_reads_preserve_io_error() {
    struct FailingReader;
    impl AsyncRead for FailingReader {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _context: &mut std::task::Context<'_>,
            _buffer: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Err(std::io::Error::other("fixture read failure")))
        }
    }
    let result = read(FailingReader, Arc::new(AtomicUsize::new(0)), 100).await;
    assert!(matches!(
        result,
        Err(Error::Io {
            operation: "read output",
            ..
        })
    ));
}

#[tokio::test]
async fn a_broken_input_pipe_does_not_leave_a_supervisor_running() {
    let host = LimitedLocalHost::new(100);
    let result = host
        .run(&ExecRequest::new(["true"]).with_stdin(vec![b'x'; 300_000]))
        .await;
    assert!(
        result.is_ok()
            || matches!(
                result,
                Err(Error::Io {
                    operation: "write to stdin",
                    ..
                })
            )
    );
    host.drain().await;
    assert_eq!(host.state.active.load(Ordering::SeqCst), 0);
}

#[test]
fn missing_child_pipe_is_a_collection_error() {
    let result = pipe::<tokio::process::ChildStdout>(None, "stdout");
    assert!(matches!(
        result,
        Err(Error::Backend {
            operation: "collect output",
            ..
        })
    ));
}

#[cfg(unix)]
#[tokio::test]
async fn cleanup_failure_retains_the_native_child_and_checked_drain_retries_it() -> Result<()> {
    let host = LimitedLocalHost::new(16);
    let mut command = crate::LocalHost::command(&ExecRequest::new(["sleep", "600"]))?;
    process::prepare(&mut command)?;
    let child = command
        .spawn()
        .map_err(|error| Error::io("fixture spawn", &error))?;
    let group = process::group(&child)?;
    let pid = child
        .id()
        .ok_or_else(|| Error::io("fixture pid", &std::io::Error::other("missing")))?;
    let injected = Err(Error::Backend {
        sandbox: crate::LOCAL.into(),
        operation: "fixture kill",
        message: "transient native failure".into(),
    });
    assert!(retain_cleanup(&host.state, child, group, injected).is_err());
    assert!(host.has_pending_cleanup());
    host.drain_checked().await?;
    assert!(!host.has_pending_cleanup());
    host.drain_checked().await?;
    #[cfg(target_os = "linux")]
    assert!(!std::path::Path::new(&format!("/proc/{pid}/status")).exists());
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn dropping_a_cleanup_retry_keeps_the_native_child_owned_for_another_retry() -> Result<()> {
    let host = LimitedLocalHost::new(16);
    let mut command = crate::LocalHost::command(&ExecRequest::new(["sleep", "600"]))?;
    process::prepare(&mut command)?;
    let child = command
        .spawn()
        .map_err(|error| Error::io("fixture spawn", &error))?;
    let group = process::group(&child)?;
    let slot = Arc::new(tokio::sync::Mutex::new(Some(child)));
    host.state
        .cleanup_failures
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(group, slot.clone());
    let held = slot.lock().await;
    let retry_host = host.clone();
    let retry = tokio::spawn(async move { retry_host.drain_checked().await });
    // The retry acquired its coordination lock and is waiting for this child slot.
    while host.state.cleanup_lock.try_lock().is_ok() {
        tokio::task::yield_now().await;
    }
    retry.abort();
    assert!(retry.await.is_err());
    assert!(held.is_some());
    assert!(host.has_pending_cleanup());
    drop(held);
    host.drain_checked().await?;
    assert!(!host.has_pending_cleanup());
    Ok(())
}
