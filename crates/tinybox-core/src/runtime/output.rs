//! Provider-owned batch observation and cooperative execution cancellation.

use crate::Result;
use async_trait::async_trait;

pub use tinybox_bus::OutputStream;

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
#[path = "output_tests.rs"]
mod tests;
