//! Module-owned bounded output journal and cooperative execution cancellation.
use std::sync::Mutex;
use tinybox_bus::{
    ExecutionFailure, ExecutionState, MAX_OUTPUT_BYTES, OutputBatch, OutputChunk, OutputStream,
};
use tinybox_core::{Error, ExecutionObserver, Result};

const FRAME_BYTES: usize = 8192;
const BATCH_BYTES: usize = 64 * 1024;

#[derive(Debug)]
struct JournalState {
    chunks: Vec<OutputChunk>,
    bytes: usize,
    state: ExecutionState,
    cancelled: bool,
}
impl Default for JournalState {
    fn default() -> Self {
        Self {
            chunks: Vec::new(),
            bytes: 0,
            state: ExecutionState::Running,
            cancelled: false,
        }
    }
}

#[derive(Debug, Default)]
pub(super) struct OutputJournal {
    state: Mutex<JournalState>,
    cancelled: tokio::sync::Notify,
}
impl OutputJournal {
    pub(super) fn read(&self, cursor: u64) -> Result<OutputBatch> {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let cursor = usize::try_from(cursor).map_err(|_| invalid_cursor())?;
        if cursor > state.chunks.len() {
            return Err(invalid_cursor());
        }
        let mut bytes = 0;
        let chunks: Vec<_> = state.chunks[cursor..]
            .iter()
            .take_while(|chunk| {
                bytes += chunk.bytes.len();
                bytes <= BATCH_BYTES
            })
            .cloned()
            .collect();
        let next_sequence = (cursor + chunks.len()) as u64;
        Ok(OutputBatch {
            chunks,
            next_sequence,
            state: state.state.clone(),
        })
    }
    pub(super) fn cancel_requested(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .cancelled
    }
    pub(super) fn cancel(&self) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .cancelled = true;
        self.cancelled.notify_waiters();
    }
    pub(super) fn finish_exit(&self, exit_code: i32) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.state == ExecutionState::Running {
            state.state = if state.cancelled {
                ExecutionState::Cancelled
            } else {
                ExecutionState::Exited { exit_code }
            };
        }
    }
    pub(super) fn finish_failed(&self, code: ExecutionFailure) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Cleanup failure remains owned until the resource collector retries it.
        if state.state == ExecutionState::Running
            || matches!(
                state.state,
                ExecutionState::Failed {
                    code: ExecutionFailure::CleanupFailed
                }
            )
        {
            state.state = ExecutionState::Failed { code };
        }
    }
    pub(super) fn cleanup_acknowledged(&self) -> bool {
        !matches!(
            self.state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .state,
            ExecutionState::Running
                | ExecutionState::Failed {
                    code: ExecutionFailure::CleanupFailed
                }
        )
    }
}
#[tinybus::__private::async_trait]
impl ExecutionObserver for OutputJournal {
    fn output(&self, stream: OutputStream, bytes: &[u8]) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.state != ExecutionState::Running {
            return Err(Error::Backend {
                sandbox: "module".into(),
                operation: "observe output",
                message: "execution already completed".into(),
            });
        }
        let total = state
            .bytes
            .checked_add(bytes.len())
            .filter(|total| *total <= MAX_OUTPUT_BYTES)
            .ok_or(Error::OutputLimitExceeded {
                limit: MAX_OUTPUT_BYTES,
            })?;
        for bytes in bytes.chunks(FRAME_BYTES) {
            let sequence = state.chunks.len() as u64;
            state.chunks.push(OutputChunk {
                sequence,
                stream,
                bytes: bytes.to_vec(),
            });
        }
        state.bytes = total;
        Ok(())
    }
    async fn cancelled(&self) {
        let cancelled = self.cancelled.notified();
        tokio::pin!(cancelled);
        cancelled.as_mut().enable();
        if !self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .cancelled
        {
            cancelled.await;
        }
    }
}
fn invalid_cursor() -> Error {
    Error::Backend {
        sandbox: "module".into(),
        operation: "read output",
        message: "invalid output cursor".into(),
    }
}
#[cfg(test)]
#[path = "output_tests.rs"]
mod tests;
