//! Serialized requests and results for the `TinyBox` module.
//!
//! This crate has no bus connection, executor, native backend, or policy.
//! A caller applies its own authorization before sending these requests.
//!
//! ```
//! use tinybox_bus::{ProcessRef, ResourceId};
//! let process = ProcessRef {
//!     resource: ResourceId("caller-reservation-1".into()),
//!     process: ResourceId("caller-process-1".into()),
//! };
//! assert_eq!(process.resource.0, "caller-reservation-1");
//! ```

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Maximum reservation identifier length in bytes.
pub const MAX_ID_BYTES: usize = 128;
/// Maximum live resources in a module instance.
pub const MAX_ACTIVE_RESOURCES: usize = 64;
/// Maximum live processes or queued startups in one resource.
pub const MAX_PROCESSES_PER_RESOURCE: usize = 64;
/// Maximum unused reservations, reclaimed when consumed, closed, or expired.
pub const MAX_RESERVATIONS: usize = 4096;
/// Idle lifetime of an unused reservation, in seconds.
pub const RESERVATION_TTL_SECS: u64 = 60;
/// Maximum combined stdout and stderr bytes collected by the module host.
pub const MAX_OUTPUT_BYTES: usize = 1024 * 1024;
/// Stable error name for module admission capacity exhaustion.
pub const RESOURCE_LIMIT: &str = "ai.tinyhumans.tinybox.Error.ResourceLimit";

/// Well-known module interface.
pub const INTERFACE: &str = "ai.tinyhumans.tinybox.Box";
/// Module object path.
pub const OBJECT_PATH: &str = "/ai/tinyhumans/tinybox/Box";
/// Supported additive methods, including the original discovery operation.
pub const METHODS: &[&str] = &[
    "Describe",
    "Create",
    "Exec",
    "Inspect",
    "Close",
    "Spawn",
    "IsRunning",
    "Cancel",
    "AnalyzeShell",
    "Reserve",
    "Capabilities",
    "Shutdown",
];

/// Stable error name for an unknown or closed module resource.
pub const UNKNOWN_RESOURCE: &str = "ai.tinyhumans.tinybox.Error.UnknownResource";
/// Stable error name for a process not issued for the selected resource.
pub const UNKNOWN_PROCESS: &str = "ai.tinyhumans.tinybox.Error.UnknownProcess";
/// Stable error name for a backend the module cannot construct.
pub const UNSUPPORTED_BACKEND: &str = "ai.tinyhumans.tinybox.Error.UnsupportedBackend";
/// Stable error name for an operation without acknowledged native ownership.
pub const UNSUPPORTED_OPERATION: &str = "ai.tinyhumans.tinybox.Error.UnsupportedOperation";
/// Stable error name for an identifier already reserved by this module instance.
pub const DUPLICATE_ID: &str = "ai.tinyhumans.tinybox.Error.DuplicateId";
/// Stable error name for an empty reservation identifier.
pub const INVALID_ID: &str = "ai.tinyhumans.tinybox.Error.InvalidId";
/// Stable error name when combined output exceeds the collection budget.
pub const OUTPUT_LIMIT: &str = "ai.tinyhumans.tinybox.Error.OutputLimit";
/// Stable error name when Close cancels collected execution.
pub const EXEC_CANCELLED: &str = "ai.tinyhumans.tinybox.Error.ExecCancelled";
/// Stable error name for a native backend operation failure.
pub const BACKEND_ERROR: &str = "ai.tinyhumans.tinybox.Error.Backend";

/// Opaque module-minted reservation identifier bound by one module instance.
/// IDs use ASCII letters, digits, hyphens, or underscores, up to [`MAX_ID_BYTES`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ResourceId(pub String);

/// Allocate a single-use startup reservation without starting native work.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReserveRequest {
    /// Reserve a resource for Create.
    Resource,
    /// Reserve a process for Spawn, bound to the selected resource.
    Process(ResourceId),
}

/// Backend operations with acknowledged native ownership in this module build.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleCapabilities {
    /// Backends accepted by Create; no fallback is performed.
    pub create_backends: Vec<String>,
    /// Backends accepted by bounded collected Exec.
    pub exec_backends: Vec<String>,
    /// Backends accepted by supervised Spawn/Cancel.
    pub spawn_backends: Vec<String>,
}

/// A workspace supplied to a backend; unsupported sources are refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Workspace {
    /// Existing directory on the selected host.
    Directory(String),
    /// OCI image reference.
    Image(String),
}

/// Allocate a local-host sandbox; the backend is always explicit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateRequest {
    /// Module-minted Resource reservation, known before native startup.
    pub resource: ResourceId,
    /// Requested backend, such as `docker`, `namespace`, or `passthrough`.
    pub backend: String,
    /// Workspace to materialize.
    pub workspace: Workspace,
    /// Variables inherited by commands.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
}

/// A command inside an existing resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecRequest {
    /// Opaque box identifier.
    pub resource: ResourceId,
    /// Unshelled program and arguments.
    pub argv: Vec<String>,
    /// Optional working directory on the host or inside the sandbox.
    #[serde(default)]
    pub cwd: Option<String>,
    /// Environment overrides.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// Bytes for standard input.
    #[serde(default)]
    pub stdin: Option<Vec<u8>>,
}

/// Collected command output; a nonzero exit code is a successful transport reply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecOutput {
    /// Process exit status.
    pub exit_code: i32,
    /// Unmodified standard output.
    pub stdout: Vec<u8>,
    /// Unmodified standard error.
    pub stderr: Vec<u8>,
}

/// Current resource state, without native handles or backend implementation types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceInfo {
    /// Opaque identifier reserved by this module instance.
    pub resource: ResourceId,
    /// Explicit backend selected at creation.
    pub backend: String,
    /// Backend-reported lifecycle state.
    pub state: String,
}

/// Start a detached process under a caller-known reservation identifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpawnRequest {
    /// Module-minted Process(resource) reservation, known before native startup.
    pub process: ResourceId,
    /// Command inside the selected resource.
    pub command: ExecRequest,
}

/// A module-owned detached process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessRef {
    /// Resource in which the process runs.
    pub resource: ResourceId,
    /// Opaque caller-known process reservation identifier.
    pub process: ResourceId,
}

/// Structural shell facts. These do not grant permission or choose an access tier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShellAnalysis {
    /// Live shell segments after quoted heredoc bodies are removed.
    pub segments: Vec<String>,
    /// Whether shell syntax can execute hidden commands.
    pub hidden_execution: bool,
    /// Whether an unquoted redirect occurs outside heredoc data.
    pub redirection: bool,
}

#[cfg(test)]
#[path = "lib_tests.rs"]
mod tests;
