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
