//! Native directory-jail requests; enforcement remains inside the module.
use serde::{Deserialize, Serialize};

/// Required treatment of the native provider's declared constraints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JailEnforcement {
    /// Require every requested filesystem, network and subprocess constraint.
    Enforced,
    /// Accept the provider's advertised partial constraints after host approval.
    Declared,
}

/// Approved native grants for one execution in a local directory resource.
/// The resource workspace is the writable root; the host retains approval policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeJailConfig {
    /// Existing absolute paths granted read and execute access.
    pub read_only: Vec<String>,
    /// Existing absolute paths additionally granted write access.
    pub read_write: Vec<String>,
    /// Whether outgoing network access is permitted.
    pub allow_net: bool,
    /// Whether child processes are permitted.
    pub allow_subprocess: bool,
    /// Required constraint enforcement, with no implicit weaker fallback.
    pub enforcement: JailEnforcement,
    /// Require the provider to meet the process-isolation security floor.
    pub require_process_isolation: bool,
    /// Absolute paths the child may neither read nor write, even where the
    /// root or a grant would otherwise reach them (credential stores, for a
    /// provider that reads allow-by-default). A path that does not exist yet is
    /// kept and resolved again just before spawn, except that the bubblewrap
    /// backend refuses a missing denial inside one of the jail's mounts: it
    /// would have to create the path to mask it. Added in contract 1.20; empty
    /// by default.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny_read: Vec<String>,
    /// Optional hard resource limits; omitted for compatibility with older requests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<crate::ResourceLimits>,
    /// File or directory names the child may neither read nor write wherever
    /// they appear (a project's `.npmrc`, say), where [`Self::deny_read`] takes
    /// exact paths. Each is one path component: not empty, not `.` or `..`, and
    /// without a separator, quote or NUL. Only a backend that can deny by name
    /// (Seatbelt) admits a request carrying any; every other backend refuses
    /// it rather than ignoring it. Added in contract 2.5; empty by default.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny_read_names: Vec<String>,
}

/// The most restrictive request: no grants beyond the root, no network, no
/// child processes, every constraint enforced and the process-isolation floor
/// required. A host builds on it with `..NativeJailConfig::default()`, so a
/// field added to the contract later does not break its code.
impl Default for NativeJailConfig {
    fn default() -> Self {
        Self {
            read_only: Vec::new(),
            read_write: Vec::new(),
            allow_net: false,
            allow_subprocess: false,
            enforcement: JailEnforcement::Enforced,
            require_process_isolation: true,
            deny_read: Vec::new(),
            resources: None,
            deny_read_names: Vec::new(),
        }
    }
}

/// Hard resource limits requested by the contract 2.1 native jail members.
/// Each dimension is independently optional so a backend can enforce a real
/// supported subset without weakening a requested limit. Disk is represented
/// explicitly so implementations must refuse it when they cannot enforce it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeJailResourceRequest {
    /// CPU budget in thousandths of one CPU (for example, 1 is 0.1%).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_millis: Option<u64>,
    /// Maximum resident memory in bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_bytes: Option<u64>,
    /// Maximum number of processes and threads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pids_max: Option<u64>,
    /// Maximum writable disk bytes. Backends without a hard disk quota refuse.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_bytes: Option<u64>,
}

/// Source-compatible extension of [`NativeJailConfig`] for contract 2.1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeJailRequest {
    /// Existing filesystem, network and process jail configuration.
    pub jail: NativeJailConfig,
    /// Additional hard resource dimensions; any explicit unsupported one fails closed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<NativeJailResourceRequest>,
}

#[cfg(test)]
#[path = "jail_tests.rs"]
mod tests;
