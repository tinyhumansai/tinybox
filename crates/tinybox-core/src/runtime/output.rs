//! Output streams and provider-proven resource termination causes.

use crate::Result;
use async_trait::async_trait;

pub use tinybox_bus::OutputStream;

/// A resource-limit termination proven by provider-owned runtime evidence.
///
/// Backends must not infer these causes from a signal or exit code alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TerminationCause {
    /// The Linux cgroup v2 CPU controller throttled work under its quota.
    CpuQuota,
}

/// Receives bounded output batches inside the provider's execution runtime.
///
/// Module adapters implement this with a bounded journal and a cancellation
/// signal. This trait does not grant permission, run host callbacks, or expose
/// native handles. Returning an output error must terminate collection and
/// trigger the provider's normal native cleanup.
#[async_trait]
pub trait ExecutionObserver: std::fmt::Debug + Send + Sync + 'static {
    /// Observe original bytes from one pipe in arrival order.
    ///
    /// # Errors
    /// Returns an error if the bounded journal cannot accept this batch.
    fn output(&self, stream: OutputStream, bytes: &[u8]) -> Result<()>;

    /// Record a provider-proven resource termination while execution is owned.
    fn termination_cause(&self, _cause: TerminationCause) {}

    /// Resolve when the owning module requests execution cancellation.
    ///
    /// The provider acknowledges cancellation only after killing and joining
    /// native execution. Dropping the calling future retains the provider's
    /// existing supervisor/cleanup ownership guarantees.
    async fn cancelled(&self) {
        std::future::pending::<()>().await;
    }
}

#[cfg(test)]
#[derive(Debug)]
struct DefaultTerminationObserver;

#[cfg(test)]
#[async_trait]
impl ExecutionObserver for DefaultTerminationObserver {
    fn output(&self, _: OutputStream, _: &[u8]) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
#[path = "output_tests.rs"]
mod tests;
