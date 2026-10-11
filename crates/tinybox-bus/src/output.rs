//! Serialized streaming output and acknowledged terminal states.
use serde::{Deserialize, Serialize};

/// The original native pipe that produced a chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputStream {
    /// Standard output.
    Stdout,
    /// Standard error.
    Stderr,
}

/// A bounded batch member in the module's observation order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputChunk {
    /// Zero-based event position within this execution.
    pub sequence: u64,
    /// Source pipe.
    pub stream: OutputStream,
    /// Unmodified bytes, including non-UTF-8 output.
    pub bytes: Vec<u8>,
}

/// Safe failure vocabulary; it contains no arguments, content, or paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionFailure {
    /// The native operation could not start.
    StartFailed,
    /// Combined output exceeded the execution budget.
    OutputLimit,
    /// Reading or delivering output failed.
    OutputFailed,
    /// Native kill/reap remains unacknowledged and can be retried.
    CleanupFailed,
    /// The provider failed the operation.
    BackendFailed,
}

/// Successful exit and cancellation acknowledge native cleanup. A failed
/// cleanup remains owned by the module for an explicit retry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecutionState {
    /// Execution or its cleanup is still in progress.
    Running,
    /// Native execution completed, including a nonzero result.
    Exited {
        /// Native process exit status.
        exit_code: i32,
    },
    /// Cancellation has completed native cleanup.
    Cancelled,
    /// A terminal operation error or a retained cleanup failure.
    Failed {
        /// Safe category of the failure.
        code: ExecutionFailure,
    },
}

/// A replayable, bounded output read without native resources.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputBatch {
    /// Ordered chunks starting at the requested sequence.
    pub chunks: Vec<OutputChunk>,
    /// Inclusive sequence for the next read; unchanged after an empty read.
    pub next_sequence: u64,
    /// Native execution/cleanup state at the time of this read.
    pub state: ExecutionState,
}

#[cfg(test)]
#[path = "output_tests.rs"]
mod tests;
