//! The vocabulary a sandbox uses to describe itself.

use std::fmt;

/// How strongly a sandbox separates guest code from the host.
///
/// The ordering is meaningful and deliberate: each level subsumes the ones
/// below it, so [`IsolationLevel::is_at_least`] can answer "is this strong
/// enough" without callers hand-rolling a comparison table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum IsolationLevel {
    /// No confinement. The workload is an ordinary host process with the
    /// launching user's full privileges.
    None,
    /// The workload runs under a separate user or working directory, but shares
    /// the host's process table and filesystem view.
    Process,
    /// Separate namespaces and cgroups. The workload cannot see host processes
    /// or escape its root, but shares the host kernel.
    Kernel,
    /// A separate kernel behind a hypervisor boundary.
    Hardware,
}

impl IsolationLevel {
    /// Whether this level is at least as strong as `floor`.
    #[must_use]
    pub const fn is_at_least(self, floor: Self) -> bool {
        (self as u8) >= (floor as u8)
    }
}

impl fmt::Display for IsolationLevel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::None => "none",
            Self::Process => "process",
            Self::Kernel => "kernel",
            Self::Hardware => "hardware",
        };
        formatter.write_str(text)
    }
}

/// What a sandbox can capture when asked for a snapshot.
///
/// A namespaces or container sandbox can freeze a filesystem but not live
/// memory; only a hypervisor-backed sandbox can do both. Callers that need a
/// resumable in-memory state must check for
/// [`SnapshotSupport::FilesystemAndMemory`] rather than assuming.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum SnapshotSupport {
    /// Snapshots are not available at all.
    None,
    /// The filesystem can be captured and restored; running processes cannot.
    Filesystem,
    /// Both the filesystem and live guest memory can be captured and restored.
    FilesystemAndMemory,
}

impl SnapshotSupport {
    /// Whether a snapshot preserves the filesystem.
    #[must_use]
    pub const fn captures_filesystem(self) -> bool {
        !matches!(self, Self::None)
    }

    /// Whether a snapshot preserves live guest memory.
    #[must_use]
    pub const fn captures_memory(self) -> bool {
        matches!(self, Self::FilesystemAndMemory)
    }
}

impl fmt::Display for SnapshotSupport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::None => "no snapshots",
            Self::Filesystem => "filesystem snapshots",
            Self::FilesystemAndMemory => "filesystem and memory snapshots",
        };
        formatter.write_str(text)
    }
}

/// A single behavior a caller can require of a sandbox.
///
/// This is the unit [`SandboxCapabilities::require`] reports on, so it appears
/// verbatim in [`Error::Unsupported`](crate::error::Error::Unsupported) messages.
///
/// [`SandboxCapabilities::require`]: crate::capability::SandboxCapabilities::require
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Capability {
    /// Capturing and restoring the box filesystem.
    FilesystemSnapshot,
    /// Capturing and restoring live guest memory.
    MemorySnapshot,
    /// Branching a snapshot into an independent box.
    Fork,
    /// Freezing and thawing a running box.
    PauseResume,
    /// Publishing a guest port to the host.
    PortForward,
}

impl fmt::Display for Capability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::FilesystemSnapshot => "filesystem snapshots",
            Self::MemorySnapshot => "memory snapshots",
            Self::Fork => "forking",
            Self::PauseResume => "pause and resume",
            Self::PortForward => "port forwarding",
        };
        formatter.write_str(text)
    }
}
