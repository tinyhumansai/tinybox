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

mod shell;
pub use shell::{CommandAnalysis, CommandClass, CommandSegment};
mod files;
pub use files::{
    AbortFileWriteRequest, BeginFileReadRequest, BeginFileWriteRequest, FileChunk, FileReadInfo,
    FileWriteInfo, FileWriteProgress, FinishFileReadRequest, FinishFileWriteRequest,
    ReadFileChunkRequest, WriteFileChunkRequest,
};

/// Wire vocabulary version, independent of the release workflow's package version.
///
/// 1.0 denotes the original discovery-only surface. 1.1 adds resource
/// reservations, owned lifecycle/operations, capabilities and terminal shutdown.
/// 1.2 adds host selection, container networking/ports, and owned forwards.
/// 1.3 adds native jail discovery.
/// 1.4 adds detailed shell facts for host execution policy. 1.5 adds bounded
/// file transfer for mounted workspaces. 1.6 adds bounded live native output.
pub const CONTRACT_VERSION: (u32, u32) = (1, 6);

/// Whether this host vocabulary can bind to a module's advertised version.
/// The major must match and the module's minor must include every host member.
#[must_use]
pub fn is_compatible(module: (u32, u32)) -> bool {
    module.0 == CONTRACT_VERSION.0 && module.1 >= CONTRACT_VERSION.1
}

/// Maximum reservation identifier length in bytes.
pub const MAX_ID_BYTES: usize = 128;
/// Maximum live resources in a module instance.
pub const MAX_ACTIVE_RESOURCES: usize = 64;
/// Maximum live processes or queued startups in one resource.
pub const MAX_PROCESSES_PER_RESOURCE: usize = 64;
/// Maximum live forwarding tunnels per resource.
pub const MAX_FORWARDS_PER_RESOURCE: usize = 64;
/// Maximum unused reservations, reclaimed when consumed, closed, or expired.
pub const MAX_RESERVATIONS: usize = 4096;
/// Idle lifetime of an unused reservation, in seconds.
pub const RESERVATION_TTL_SECS: u64 = 60;
/// Maximum combined stdout and stderr bytes collected by the module host.
pub const MAX_OUTPUT_BYTES: usize = 1024 * 1024;
/// Maximum bytes returned or accepted by one file-transfer chunk.
pub const MAX_FILE_CHUNK_BYTES: usize = 64 * 1024;
/// Maximum total bytes accepted by one file write.
pub const MAX_FILE_BYTES: u64 = 256 * 1024 * 1024;
/// Maximum read and write handles held by one resource.
pub const MAX_FILE_TRANSFERS_PER_RESOURCE: usize = 8;
/// Maximum UTF-8 path length accepted for a workspace file.
pub const MAX_FILE_PATH_BYTES: usize = 4096;
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
    "Forward",
    "CloseForward",
    "JailStatus",
    "AnalyzeCommand",
    "BeginFileRead",
    "ReadFileChunk",
    "FinishFileRead",
    "BeginFileWrite",
    "WriteFileChunk",
    "FinishFileWrite",
    "AbortFileWrite",
    "StartExec",
    "ReadOutput",
    "ReleaseOutput",
];

/// Facts about the detected native directory-jail backend.
/// Hosts apply their own execution policy to these facts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JailStatus {
    /// Stable backend identifier.
    pub backend: String,
    /// Whether this build can apply the detected backend.
    pub available: bool,
    /// Declared process isolation: none, process, kernel, or hardware.
    pub isolation: String,
    /// Whether process isolation and filesystem enforcement meet the security floor.
    pub suitable_for_untrusted_code: bool,
    /// Filesystem constraint: unsupported, best effort, or enforced.
    pub filesystem: String,
    /// Network constraint: unsupported, best effort, or enforced.
    pub network: String,
    /// Subprocess constraint: unsupported, best effort, or enforced.
    pub subprocess: String,
}

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
/// Stable error name for an invalid workspace-relative file path.
pub const INVALID_FILE_PATH: &str = "ai.tinyhumans.tinybox.Error.InvalidFilePath";
/// Stable error name for a missing or mismatched file-transfer handle.
pub const UNKNOWN_FILE_TRANSFER: &str = "ai.tinyhumans.tinybox.Error.UnknownFileTransfer";
/// Stable error name for a file-transfer size or handle limit.
pub const FILE_LIMIT: &str = "ai.tinyhumans.tinybox.Error.FileLimit";
/// Stable error name for an invalid file-transfer offset or chunk.
pub const INVALID_FILE_CHUNK: &str = "ai.tinyhumans.tinybox.Error.InvalidFileChunk";
/// Stable error name when safe workspace file access is unavailable.
pub const FILE_UNSUPPORTED: &str = "ai.tinyhumans.tinybox.Error.FileUnsupported";
/// Stable error name for a workspace file operation failure.
pub const FILE_ERROR: &str = "ai.tinyhumans.tinybox.Error.FileOperation";

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
    /// Reserve a forward associated with a resource.
    Forward(ResourceId),
    /// Reserve a workspace file reader associated with a resource.
    FileRead(ResourceId),
    /// Reserve a staged workspace file writer associated with a resource.
    FileWrite(ResourceId),
}

/// Backend operations with acknowledged native ownership in this module build.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleCapabilities {
    /// Wire vocabulary served by the artifact, independent of package version.
    pub contract_version: (u32, u32),
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

/// Which host executes the selected sandbox and its commands.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum HostConfig {
    /// Run on the module's machine.
    #[default]
    Local,
    /// Reach a machine using the host's OpenSSH client and configuration.
    Ssh(SshHostConfig),
}

/// Explicit OpenSSH target and host-key policy for a remote host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshHostConfig {
    /// Host name or `user@host`, passed as one OpenSSH destination argument.
    pub destination: String,
    /// Optional SSH port override.
    #[serde(default)]
    pub port: Option<u16>,
    /// Optional private-key path on the module host.
    #[serde(default)]
    pub identity: Option<String>,
    /// Optional known-hosts path on the module host.
    #[serde(default)]
    pub known_hosts: Option<String>,
    /// Whether to trust an unknown host key on first connection.
    #[serde(default)]
    pub accept_new_host_key: bool,
}

/// Network access policy applied by a sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum NetworkPolicy {
    /// Disable all network access.
    #[default]
    Denied,
    /// Permit outbound connections without publishing inbound ports.
    Egress,
    /// Permit unrestricted network access.
    Open,
}

/// CPU, memory, process, and disk limits requested for a sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceLimits {
    /// CPU allowance in thousandths of a core.
    pub cpu_millis: u32,
    /// Maximum resident memory in bytes.
    pub memory_bytes: u64,
    /// Maximum number of processes and threads.
    pub pids_max: u32,
    /// Maximum writable filesystem size in bytes.
    pub disk_bytes: u64,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            cpu_millis: 2_000,
            memory_bytes: 2 * 1024 * 1024 * 1024,
            pids_max: 512,
            disk_bytes: 8 * 1024 * 1024 * 1024,
        }
    }
}

/// A guest port published by the sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortMapping {
    /// Port inside the sandbox.
    pub guest: u16,
    /// Requested host port, or `None` to let the sandbox choose one.
    #[serde(default)]
    pub host: Option<u16>,
}

/// A guest port and the effective host port assigned by the sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishedPort {
    /// Port inside the sandbox.
    pub guest: u16,
    /// Effective port on the selected host.
    pub host: u16,
}

/// Allocate a local-host sandbox; the backend is always explicit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateRequest {
    /// Module-minted Resource reservation, known before native startup.
    pub resource: ResourceId,
    /// Requested backend, such as `docker`, `namespace`, or `passthrough`.
    pub backend: String,
    /// Host on which the backend operates; defaults to the module machine.
    #[serde(default)]
    pub host: HostConfig,
    /// Workspace to materialize.
    pub workspace: Workspace,
    /// Network policy enforced by the sandbox.
    #[serde(default)]
    pub network: NetworkPolicy,
    /// Resource limits enforced by the sandbox.
    #[serde(default)]
    pub resources: ResourceLimits,
    /// Guest ports published on the selected host.
    #[serde(default)]
    pub ports: Vec<PortMapping>,
    /// Variables inherited by commands.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
}

impl Default for CreateRequest {
    fn default() -> Self {
        Self {
            resource: ResourceId(String::new()),
            backend: String::new(),
            host: HostConfig::default(),
            workspace: Workspace::Directory(String::new()),
            network: NetworkPolicy::default(),
            resources: ResourceLimits::default(),
            ports: Vec::new(),
            env: BTreeMap::new(),
        }
    }
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
    /// Effective host ports assigned to requested guest ports.
    #[serde(default)]
    pub published_ports: Vec<PublishedPort>,
}

/// Open a gateway to a published guest port using a caller-known reservation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForwardRequest {
    /// Resource whose host published the guest port.
    pub resource: ResourceId,
    /// Module-minted forward reservation.
    pub forward: ResourceId,
    /// Published guest port to reach.
    pub guest_port: u16,
}

/// An open gateway endpoint; the module owns its tunnel until `CloseForward`,
/// resource Close, or Shutdown.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForwardInfo {
    /// Resource whose host published the guest port.
    pub resource: ResourceId,
    /// Caller-known opaque forwarding handle.
    pub forward: ResourceId,
    /// Local address accepting connections through this gateway.
    pub local_address: String,
}

/// Close an opaque forward previously opened for a resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloseForwardRequest {
    /// Resource owning the forward.
    pub resource: ResourceId,
    /// Opaque forward handle returned by Reserve.
    pub forward: ResourceId,
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

mod output;
pub use output::{ExecutionFailure, ExecutionState, OutputBatch, OutputChunk, OutputStream};
