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
];

/// Stable error name for an unknown or closed module resource.
pub const UNKNOWN_RESOURCE: &str = "ai.tinyhumans.tinybox.Error.UnknownResource";
/// Stable error name for a process not issued for the selected resource.
pub const UNKNOWN_PROCESS: &str = "ai.tinyhumans.tinybox.Error.UnknownProcess";
/// Stable error name for a backend the module cannot construct.
pub const UNSUPPORTED_BACKEND: &str = "ai.tinyhumans.tinybox.Error.UnsupportedBackend";
/// Stable error name for an identifier already reserved by this module instance.
pub const DUPLICATE_ID: &str = "ai.tinyhumans.tinybox.Error.DuplicateId";
/// Stable error name for an empty reservation identifier.
pub const INVALID_ID: &str = "ai.tinyhumans.tinybox.Error.InvalidId";
/// Stable error name for a native backend operation failure.
pub const BACKEND_ERROR: &str = "ai.tinyhumans.tinybox.Error.Backend";

/// Opaque caller-known reservation identifier bound by one module instance.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ResourceId(pub String);

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
    /// Caller-known identifier, reserved once so a lost reply can be closed.
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
    /// Never-reused identifier, known before the startup reply arrives.
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
