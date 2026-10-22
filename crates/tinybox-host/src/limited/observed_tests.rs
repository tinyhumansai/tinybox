//! Native pipe observation and cleanup regressions.
use super::*;
use tinybox_core::{ExecutionObserver, OutputStream};

#[derive(Debug, Default)]
pub(super) struct Observer {
    chunks: Mutex<Vec<(OutputStream, Vec<u8>)>>,
    cancelled: std::sync::atomic::AtomicBool,
    notify: tokio::sync::Notify,
    first: Mutex<Option<oneshot::Sender<()>>>,
}
impl Observer {
    pub(super) fn with_first() -> (Arc<Self>, oneshot::Receiver<()>) {
        let (first, received) = oneshot::channel();
        (
            Arc::new(Self {
                first: Mutex::new(Some(first)),
                ..Self::default()
            }),
            received,
        )
    }
    pub(super) fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
    }
}
#[async_trait]
impl ExecutionObserver for Observer {
    fn output(&self, stream: OutputStream, bytes: &[u8]) -> Result<()> {
        self.chunks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push((stream, bytes.to_vec()));
        if let Some(first) = self
            .first
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            let _ = first.send(());
        }
        Ok(())
    }
    async fn cancelled(&self) {
        let cancelled = self.notify.notified();
        tokio::pin!(cancelled);
        cancelled.as_mut().enable();
        if !self.cancelled.load(Ordering::SeqCst) {
            cancelled.await;
        }
    }
}

#[tokio::test]
async fn live_observation_preserves_pipe_bytes_and_collected_result() -> Result<()> {
    let observer = Arc::new(Observer::default());
    let host = LimitedLocalHost::new(64);
    let output = host
        .run_observed(
            &ExecRequest::new(["/bin/sh", "-c", "printf abc; printf def >&2; exit 7"]),
            observer.clone(),
        )
        .await?;
    assert_eq!(output.stdout, b"abc");
    assert_eq!(output.stderr, b"def");
    assert_eq!(output.exit_code, 7);
    let chunks = observer
        .chunks
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for (stream, expected) in [
        (OutputStream::Stdout, b"abc"),
        (OutputStream::Stderr, b"def"),
    ] {
        let actual: Vec<u8> = chunks
            .iter()
            .filter(|(source, _)| *source == stream)
            .flat_map(|(_, bytes)| bytes.iter().copied())
            .collect();
        assert_eq!(actual, expected);
    }
    Ok(())
}

#[tokio::test]
async fn cancellation_acknowledges_native_cleanup_after_live_output() -> Result<()> {
    let (first, received) = oneshot::channel();
    let observer = Arc::new(Observer {
        first: Mutex::new(Some(first)),
        ..Observer::default()
    });
    let host = LimitedLocalHost::new(64);
    let runner = host.clone();
    let events = observer.clone();
    let task = tokio::spawn(async move {
        runner
            .run_observed(
                &ExecRequest::new(["/bin/sh", "-c", "printf ready; exec sleep 600"]),
                events,
            )
            .await
    });
    let first = tokio::time::timeout(std::time::Duration::from_secs(5), received).await;
    observer.cancel();
    let result = task.await.map_err(|error| {
        Error::io(
            "join observer fixture",
            &std::io::Error::other(error.to_string()),
        )
    })?;
    assert!(
        first.is_ok_and(|first| first.is_ok()),
        "output must arrive while native execution is still running"
    );
    assert!(result.is_err());
    assert_eq!(host.state.active.load(Ordering::SeqCst), 0);
    assert!(!host.has_pending_cleanup());
    Ok(())
}

#[derive(Debug)]
struct RefusingObserver;
#[async_trait]
impl ExecutionObserver for RefusingObserver {
    fn output(&self, _: OutputStream, _: &[u8]) -> Result<()> {
        Err(Error::io(
            "deliver fixture output",
            &std::io::Error::other("receiver closed"),
        ))
    }
}

#[tokio::test]
async fn a_failed_live_receiver_stops_and_reaps_native_execution() -> Result<()> {
    let host = LimitedLocalHost::new(64);
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        host.run_observed(
            &ExecRequest::new(["/bin/sh", "-c", "printf ready; exec sleep 600"]),
            Arc::new(RefusingObserver),
        ),
    )
    .await;
    assert!(result.is_ok_and(|result| result.is_err()));
    host.drain_checked().await?;
    assert_eq!(host.state.active.load(Ordering::SeqCst), 0);
    assert!(!host.has_pending_cleanup());
    Ok(())
}

#[tokio::test]
async fn live_observation_keeps_the_shared_stdout_stderr_budget() -> Result<()> {
    let host = LimitedLocalHost::new(6);
    let observer = Arc::new(Observer::default());
    let result = host
        .run_observed(
            &ExecRequest::new(["/bin/sh", "-c", "printf abcd; printf efgh >&2"]),
            observer.clone(),
        )
        .await;
    assert!(result.is_err());
    let delivered: usize = observer
        .chunks
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .map(|(_, bytes)| bytes.len())
        .sum();
    assert!(
        delivered <= 6,
        "over-budget bytes must never reach the receiver"
    );
    host.drain_checked().await?;
    assert_eq!(host.state.active.load(Ordering::SeqCst), 0);
    assert!(!host.has_pending_cleanup());
    Ok(())
}

#[derive(Debug, Default)]
struct PanickingObserver(Mutex<Option<i32>>);
#[async_trait]
impl ExecutionObserver for PanickingObserver {
    #[allow(
        clippy::panic,
        reason = "exercise native ownership across a receiver panic"
    )]
    fn output(&self, _: OutputStream, bytes: &[u8]) -> Result<()> {
        if let Ok(text) = std::str::from_utf8(bytes)
            && let Ok(group) = text.trim().parse::<i32>()
        {
            *self
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(group);
        }
        panic!("fixture receiver panicked");
    }
}
impl Drop for PanickingObserver {
    fn drop(&mut self) {
        // A failing regression must not leave its fixture descendants behind.
        if let Some(group) = *self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
        {
            let _ = nix::sys::signal::killpg(
                nix::unistd::Pid::from_raw(group),
                nix::sys::signal::Signal::SIGKILL,
            );
        }
    }
}
#[tokio::test]
async fn a_panicking_receiver_retains_native_cleanup_ownership() -> Result<()> {
    let host = LimitedLocalHost::new(64);
    let observer = Arc::new(PanickingObserver::default());
    let result = host
        .run_observed(
            &ExecRequest::new(["/bin/sh", "-c", "sleep 600 & printf '%s' $$; wait"]),
            observer,
        )
        .await;
    assert!(result.is_err());
    assert!(
        host.has_pending_cleanup(),
        "supervisor panic must retain the native child for acknowledged cleanup"
    );
    host.drain_checked().await?;
    assert!(!host.has_pending_cleanup());
    assert_eq!(host.state.active.load(Ordering::SeqCst), 0);
    Ok(())
}

/// Exercise the public retry while an observed native child is still running.
pub(super) async fn retry_during_active_execution(host: Arc<dyn Host>) -> Result<(bool, bool)> {
    use std::future::Future;
    use std::task::Poll;
    let (observer, started) = Observer::with_first();
    let runner = host.clone();
    let running = tokio::spawn(async move {
        runner
            .run_observed(
                &ExecRequest::new(["/bin/sh", "-c", "printf ready; exec /bin/sleep 600"]),
                observer,
            )
            .await
    });
    started
        .await
        .map_err(|error| Error::io("fixture readiness", &std::io::Error::other(error)))?;
    let mut retry = Box::pin(host.retry_observed_cleanup());
    let completion =
        std::future::poll_fn(|context| Poll::Ready(retry.as_mut().poll(context))).await;
    let still_running = !running.is_finished();
    drop(retry);
    running.abort();
    let _ = running.await;
    Ok((matches!(completion, Poll::Ready(Ok(()))), still_running))
}

#[tokio::test]
async fn cleanup_retry_does_not_wait_for_or_cancel_an_active_local_execution() -> Result<()> {
    let host = LimitedLocalHost::new(64);
    let (completed, still_running) = retry_during_active_execution(Arc::new(host.clone())).await?;
    host.drain_checked().await?;
    assert!(completed, "cleanup retry must not join active executions");
    assert!(
        still_running,
        "cleanup retry must leave the active execution alone"
    );
    Ok(())
}

#[tokio::test]
async fn observed_shell_keeps_cwd_environment_stdin_and_output_limits() -> Result<()> {
    let root = tempfile::tempdir().map_err(|error| Error::io("create fixture", &error))?;
    let host = LimitedLocalHost::new(64);
    let request = ExecRequest::new(Vec::<String>::new())
        .with_cwd(root.path())
        .with_env("TINYBOX_SHELL_VALUE", "fixture")
        .with_env("SHELLOPTS", "errexit")
        .with_stdin("input");
    let shell = tinybox_bus::SelectShellRequest {
        command: "false; printf '%s:' \"$TINYBOX_SHELL_VALUE\"; cat; printf file > result.txt"
            .into(),
        preserve_pipeline_status: false,
        runtime_path: None,
        python_utf8: false,
    };
    let output = host
        .run_shell_observed(&request, &shell, Arc::new(Observer::default()))
        .await?;
    assert!(output.succeeded());
    assert_eq!(output.stdout, b"fixture:input");
    assert!(root.path().join("result.txt").is_file());
    let error = LimitedLocalHost::new(1)
        .run_shell_observed(&request, &shell, Arc::new(Observer::default()))
        .await
        .err();
    assert!(matches!(
        error,
        Some(Error::OutputLimitExceeded { limit: 1 })
    ));
    host.drain_checked().await?;
    Ok(())
}

#[tokio::test]
async fn a_background_process_holding_the_output_does_not_hold_the_call() -> Result<()> {
    let observer = Arc::new(Observer::default());
    let host = LimitedLocalHost::new(4096);
    let started = std::time::Instant::now();
    let output = host
        .run_observed(
            &ExecRequest::new(["/bin/sh", "-c", "printf ready; sleep 30 &"]),
            observer,
        )
        .await?;
    assert!(
        started.elapsed() < std::time::Duration::from_secs(20),
        "returned after the grace, not when the background sleep ended: {:?}",
        started.elapsed()
    );
    assert_eq!(output.stdout, b"ready");
    assert_eq!(output.exit_code, 0);
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("still holds its output open"),
        "the caller is told why: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

#[tokio::test]
async fn output_that_ends_within_the_grace_is_kept_whole() -> Result<()> {
    let observer = Arc::new(Observer::default());
    let host = LimitedLocalHost::new(4096);
    let output = host
        .run_observed(
            &ExecRequest::new(["/bin/sh", "-c", "(sleep 1; printf late) & printf early"]),
            observer,
        )
        .await?;
    assert_eq!(output.stdout, b"earlylate");
    assert!(
        output.stderr.is_empty(),
        "no note when the pipes end: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}
