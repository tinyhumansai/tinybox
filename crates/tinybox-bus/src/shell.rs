//! Shell facts returned by the compiled module for host-owned execution policy.

use serde::{Deserialize, Serialize};

/// Permission buckets in increasing order; unknown commands are classified as writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandClass {
    /// Provably observational command.
    Read,
    /// Changes state or is not provably read-only.
    Write,
    /// Reaches the network.
    Network,
    /// Installs a global or system package.
    Install,
    /// Catastrophic, irreversible, or privileged operation.
    Destructive,
}

/// Parsed facts for one live shell segment, without a host approval decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandSegment {
    /// Segment with quoted heredoc data removed.
    pub source: String,
    /// Segment after leading environment assignments are removed.
    pub command: String,
    /// Base command preserving the scanner's original case handling.
    pub basename: String,
    /// Normalized command name used for classification.
    pub normalized_name: String,
    /// Arguments in the classifier's lower-case vocabulary.
    pub arguments: Vec<String>,
    /// Generic command category; hosts decide how to gate it.
    pub class: CommandClass,
    /// Whether this segment starts with an environment assignment.
    pub leading_env_assignment: bool,
    /// Whether an environment prefix can change command execution.
    pub dangerous_env_prefix: bool,
    /// Whether the base is a generic command executor.
    pub executor: bool,
}

/// Generic parsing facts for host allowlists, approvals, and protected-path checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
// These independent syntax facts may coexist; they are not mutually exclusive states.
#[allow(clippy::struct_excessive_bools)]
pub struct CommandAnalysis {
    /// Parsed live segments in their original order.
    pub segments: Vec<CommandSegment>,
    /// Hidden command-execution syntax.
    pub hidden_execution: bool,
    /// Unquoted output redirection in the policy scanner's input.
    pub redirection: bool,
    /// Expansion or substitution markers in the policy scanner's input.
    pub expansion: bool,
    /// A tee command in the policy scanner's input.
    pub tee: bool,
    /// A single unquoted ampersand, excluding conditional chaining.
    pub background: bool,
    /// Literal tokens outside quoted heredoc data; hosts resolve and authorize paths.
    pub literal_words: Vec<String>,
}
