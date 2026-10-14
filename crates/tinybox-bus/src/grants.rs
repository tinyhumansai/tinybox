//! Host-configured filesystem grant discovery and protected-path vocabulary.
use serde::{Deserialize, Serialize};

/// Configuration used to discover toolchain and explicit filesystem grants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct LocalGrantConfig {
    /// Include existing toolchain homes and git configuration.
    pub toolchain_homes: bool,
    /// Additional read-only paths, accepting a leading tilde.
    pub extra_read_only: Vec<String>,
    /// Additional writable paths, accepting a leading tilde.
    pub extra_read_write: Vec<String>,
    /// Explicitly permit read access to `/proc`.
    pub allow_proc: bool,
}
impl Default for LocalGrantConfig {
    fn default() -> Self {
        Self {
            toolchain_homes: true,
            extra_read_only: Vec::new(),
            extra_read_write: Vec::new(),
            allow_proc: false,
        }
    }
}

/// Host-owned protected-path floor; matching ignores case and separator style.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ProtectedPaths {
    /// Forbidden path components at any depth (including credential filenames).
    pub components: Vec<String>,
    /// Forbidden consecutive path-component pairs.
    pub component_pairs: Vec<[String; 2]>,
    /// Forbidden absolute roots and their descendants. Trailing separators and
    /// Windows extended-path namespaces are normalized before matching.
    pub prefixes: Vec<String>,
    /// Credential roots whose ancestors must also never be granted.
    pub credential_roots: Vec<String>,
}

/// Request to resolve existing local grant paths, without launching a command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolveLocalGrantsRequest {
    /// Operator home; absent for hosts with no operator-home access.
    pub home: Option<String>,
    /// Toolchain and additional-grant configuration.
    pub config: LocalGrantConfig,
    /// Host's unconditional protected-path floor.
    pub protected: ProtectedPaths,
    /// Permit canonical non-UTF-8 Unix grant paths in `unix_paths`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub allow_unix_paths: bool,
}

/// Canonical existing filesystem grants beyond a workload's writable root.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalGrants {
    /// Read and executable paths.
    pub read_only: Vec<String>,
    /// Read, executable, and writable paths.
    pub read_write: Vec<String>,
    /// Canonical Unix paths whose OS bytes are not UTF-8.
    #[serde(default, skip_serializing_if = "UnixPathGrants::is_empty")]
    pub unix_paths: UnixPathGrants,
}

/// Non-UTF-8 Unix grant paths transported as their original OS bytes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnixPathGrants {
    /// Read and executable paths.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub read_only: Vec<Vec<u8>>,
    /// Read, executable, and writable paths.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub read_write: Vec<Vec<u8>>,
}

impl UnixPathGrants {
    pub(crate) fn is_empty(&self) -> bool {
        self.read_only.is_empty() && self.read_write.is_empty()
    }
}
