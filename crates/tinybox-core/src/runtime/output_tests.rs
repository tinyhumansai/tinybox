//! Defaults refuse streaming without executing a collected fallback.
use super::*;
use crate::{Error, ExecOutput, ExecRequest, Host, Result};
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Debug, Default)]
struct CountingHost(AtomicUsize);
#[async_trait]
impl Host for CountingHost {
    fn name(&self) -> &'static str {
        "fixture"
    }
    async fn run(&self, _: &ExecRequest) -> Result<ExecOutput> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(ExecOutput::new(0, Vec::new(), Vec::new()))
    }
}
#[derive(Debug)]
struct Observer;
#[async_trait]
impl ExecutionObserver for Observer {
    fn output(&self, _: OutputStream, _: &[u8]) -> Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn an_unimplemented_stream_does_not_execute_a_collected_fallback() {
    let host = CountingHost::default();
    let result = host
        .run_observed(&ExecRequest::new(["true"]), std::sync::Arc::new(Observer))
        .await;
    assert!(matches!(result, Err(Error::UnsupportedStreaming { .. })));
    assert_eq!(host.0.load(Ordering::SeqCst), 0);
}

#[test]
fn a_default_observer_does_not_spuriously_request_cancellation() {
    let observer = Observer;
    let mut future = std::pin::pin!(observer.cancelled());
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(std::future::Future::poll(future.as_mut(), &mut context).is_pending());
}
