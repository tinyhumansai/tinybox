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
    /// Approved non-UTF-8 Unix grant paths, represented by their OS bytes.
    #[serde(default, skip_serializing_if = "crate::UnixPathGrants::is_empty")]
    pub unix_paths: crate::UnixPathGrants,
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
    /// provider that reads allow-by-default). Paths that do not exist are
    /// ignored. Added in contract 1.20; empty by default.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny_read: Vec<String>,
    /// Optional hard resource limits; omitted for compatibility with older requests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<crate::ResourceLimits>,
}

#[cfg(test)]
#[path = "jail_tests.rs"]
mod tests;
