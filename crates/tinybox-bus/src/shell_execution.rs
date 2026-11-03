//! Reserved native shell execution; authorization remains caller-owned.
use crate::{CreateRequest, NativeJailConfig, ProcessRef, ResourceId, SelectShellRequest};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Start a local shell under module-owned supervision and output replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShellExecRequest {
    /// Caller-known process reservation.
    pub process: ResourceId,
    /// Existing local passthrough resource.
    pub resource: ResourceId,
    /// Shell payload and pipeline-status convention.
    pub shell: SelectShellRequest,
    /// Working directory inside the resource; absent means its root.
    #[serde(default)]
    pub cwd: Option<String>,
    /// Approved overrides on the module's safe parent environment snapshot.
    #[serde(default)]
    pub extra_env: BTreeMap<String, String>,
    /// Approved existing absolute private state directory for owned scratch.
    pub state_dir: String,
    /// Positive runtime budget, default thirty seconds, at most twenty-four hours.
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
    /// Binary input; absent closes stdin.
    #[serde(default)]
    pub stdin: Option<Vec<u8>>,
    /// Explicit native confinement; absent is ordinary local execution.
    #[serde(default)]
    pub jail: Option<NativeJailConfig>,
    /// Windows only: start the child without a console window. Ignored on
    /// other platforms.
    #[serde(default)]
    pub hide_window: bool,
}

/// Start and supervise a native shell through its first completion or yield.
/// Reservation identifiers inside `shell` are ignored and replaced by the
/// module. A yielded process remains module-owned and can be polled through
/// `ReadOutput` or stopped through `Cancel`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunNativeShellRequest {
    /// Resource configuration; its reservation identifier is ignored.
    pub create: CreateRequest,
    /// Shell configuration; resource and process identifiers are ignored.
    pub shell: ShellExecRequest,
    /// Yield when still running after this duration, if shorter than timeout.
    #[serde(default)]
    pub yield_after_ms: Option<u64>,
}

/// Result of a supervised shell call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum RunNativeShellResult {
    /// The process exited or timed out and cleanup was acknowledged.
    Finished {
        /// Process exit status, including nonzero results.
        exit_code: i32,
        /// Collected standard output bytes.
        stdout: Vec<u8>,
        /// Collected standard error bytes.
        stderr: Vec<u8>,
        /// Whether the shell exceeded its request timeout.
        timed_out: bool,
    },
    /// The process is still running and remains owned by the module.
    Running {
        /// Resource to close after process cleanup.
        resource: ResourceId,
        /// Process to poll or cancel.
        process: ProcessRef,
        /// Cursor for the next output read.
        cursor: u64,
        /// Standard output collected before yielding.
        stdout: Vec<u8>,
        /// Standard error collected before yielding.
        stderr: Vec<u8>,
    },
}
const fn default_timeout() -> u64 {
    30_000
}
