//! Interactive piped-stdio processes owned by the module.
//!
//! A caller starts one program inside the native directory jail of a local
//! resource, then streams bytes to its stdin and from its stdout and stderr
//! over the bus. Isolation is the same as `StartJailedExec`: the caller's
//! [`NativeJailConfig`] (including `deny_read`) is mandatory and is enforced
//! or the start is refused. The module never falls back to an unconfined spawn.
use crate::{NativeJailConfig, ProcessRef, ResourceId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Start one unshelled program with piped stdin, stdout and stderr.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StdioStartRequest {
    /// Module-minted `Process(resource)` reservation.
    pub process: ResourceId,
    /// Existing local passthrough directory resource; its workspace is the
    /// jail's writable root.
    pub resource: ResourceId,
    /// Program followed by its arguments; never interpreted by a shell.
    pub argv: Vec<String>,
    /// Working directory inside the resource; absent means its root.
    #[serde(default)]
    pub cwd: Option<String>,
    /// Environment on top of the module's safe parent snapshot.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// Mandatory native confinement, with the same floor as `StartJailedExec`.
    pub jail: NativeJailConfig,
}

// Environment values commonly carry credentials, so they stay out of logs.
impl std::fmt::Debug for StdioStartRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StdioStartRequest")
            .field("process", &self.process)
            .field("resource", &self.resource)
            .field("argc", &self.argv.len())
            .field("env_keys", &self.env.keys().collect::<Vec<_>>())
            .field("jail", &self.jail)
            .finish_non_exhaustive()
    }
}

/// Write bytes to the child's stdin. The call returns once every byte is
/// written to the pipe, so the caller gets backpressure from a slow child.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StdioWriteRequest {
    /// Process to write to.
    pub process: ProcessRef,
    /// Bytes to write, at most [`MAX_STDIO_WRITE_BYTES`].
    pub data: Vec<u8>,
}

impl std::fmt::Debug for StdioWriteRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StdioWriteRequest")
            .field("process", &self.process)
            .field("len", &self.data.len())
            .finish()
    }
}

/// Take buffered output, waiting up to `wait_ms` when none is ready.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StdioReadRequest {
    /// Process to read from.
    pub process: ProcessRef,
    /// Maximum bytes to return across both streams, clamped to
    /// [`MAX_STDIO_READ_BYTES`]; zero means the maximum.
    #[serde(default)]
    pub max_bytes: u32,
    /// Maximum time to wait for output when none is buffered, clamped to
    /// [`MAX_STDIO_WAIT_MS`]; zero polls without waiting.
    #[serde(default)]
    pub wait_ms: u64,
}

/// How the child ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StdioExit {
    /// The child exited with this code.
    Code(i32),
    /// The child was ended by this signal, such as a kill.
    Signal(i32),
    /// The child ended and its status is unavailable.
    Unknown,
}

/// Process state reported by `StdioStatus` and every read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StdioStatus {
    /// Whether the child has not yet been reaped.
    pub running: bool,
    /// How the child ended; absent while it runs.
    #[serde(default)]
    pub exit: Option<StdioExit>,
}

/// Output taken from the buffers, in per-stream order.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StdioChunk {
    /// Bytes taken from stdout.
    pub stdout: Vec<u8>,
    /// Bytes taken from stderr.
    pub stderr: Vec<u8>,
    /// Stdout reached end of file and its buffer is empty.
    pub stdout_closed: bool,
    /// Stderr reached end of file and its buffer is empty.
    pub stderr_closed: bool,
    /// Process state at the time of the read.
    pub status: StdioStatus,
}

impl std::fmt::Debug for StdioChunk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StdioChunk")
            .field("stdout_len", &self.stdout.len())
            .field("stderr_len", &self.stderr.len())
            .field("stdout_closed", &self.stdout_closed)
            .field("stderr_closed", &self.stderr_closed)
            .field("status", &self.status)
            .finish()
    }
}

/// Maximum bytes accepted by one `WriteStdio`.
pub const MAX_STDIO_WRITE_BYTES: usize = 64 * 1024;
/// Maximum bytes returned by one `ReadStdio`.
pub const MAX_STDIO_READ_BYTES: usize = 64 * 1024;
/// Maximum time one `ReadStdio` or `WriteStdio` blocks, in milliseconds.
pub const MAX_STDIO_WAIT_MS: u64 = 30_000;
/// Maximum buffered, unread bytes held per stream before the module stops
/// reading the child's pipe, which backpressures the child.
pub const MAX_STDIO_BUFFER_BYTES: usize = 1024 * 1024;
/// Maximum live stdio processes in one module instance.
pub const MAX_STDIO_PROCESSES: usize = 32;
/// Stable error name for a write to a stdin that is closed or broken.
pub const STDIO_CLOSED: &str = "ai.tinyhumans.tinybox.Error.StdioClosed";

#[cfg(test)]
#[path = "stdio_tests.rs"]
mod tests;
