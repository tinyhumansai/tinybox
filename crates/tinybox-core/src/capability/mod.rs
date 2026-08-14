//! What a sandbox can actually do, and how a caller is told when it cannot.
//!
//! Every [`Sandbox`](crate::runtime::Sandbox) declares a
//! [`SandboxCapabilities`] describing its real behavior. Core code checks the
//! declaration before dispatching and returns
//! [`Error::Unsupported`] rather than emulating a
//! capability badly.
//!
//! This matters most at the weak end of the range. A passthrough sandbox runs
//! a bare host process with no confinement whatsoever; if it reported the same
//! shape as a microVM, callers would believe untrusted code had been contained
//! when it had not. Declaring [`IsolationLevel::None`] keeps that honest.
//!
//! ```
//! use tinybox_core::capability::{Capability, IsolationLevel, SandboxCapabilities};
//!
//! let caps = SandboxCapabilities::PASSTHROUGH;
//! assert_eq!(caps.isolation, IsolationLevel::None);
//! assert!(caps.require("passthrough", Capability::Fork).is_err());
//! ```

use crate::error::{Error, Result};

mod types;

pub use types::{Capability, IsolationLevel, SnapshotSupport};

/// The complete set of behaviors a sandbox declares.
///
/// Construct one with [`SandboxCapabilities::new`] or start from a preset such
/// as [`SandboxCapabilities::PASSTHROUGH`] and adjust the fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct SandboxCapabilities {
    /// How strongly the sandbox separates guest code from the host.
    pub isolation: IsolationLevel,
    /// What the sandbox can capture and restore.
    pub snapshot: SnapshotSupport,
    /// Whether a snapshot can be branched into an independent box.
    pub fork: bool,
    /// Whether a running box can be frozen and thawed without losing state.
    pub pause_resume: bool,
    /// Whether a guest port can be published to the host.
    pub port_forward: bool,
}

impl SandboxCapabilities {
    /// A bare host process: reach without confinement.
    ///
    /// Useful for trusted local development, and never for untrusted code.
    pub const PASSTHROUGH: Self = Self {
        isolation: IsolationLevel::None,
        snapshot: SnapshotSupport::None,
        fork: false,
        pause_resume: false,
        port_forward: false,
    };

    /// Declare a capability set explicitly.
    #[must_use]
    pub const fn new(
        isolation: IsolationLevel,
        snapshot: SnapshotSupport,
        fork: bool,
        pause_resume: bool,
        port_forward: bool,
    ) -> Self {
        Self {
            isolation,
            snapshot,
            fork,
            pause_resume,
            port_forward,
        }
    }

    /// Whether this set includes `capability`.
    #[must_use]
    pub const fn supports(&self, capability: Capability) -> bool {
        match capability {
            Capability::FilesystemSnapshot => self.snapshot.captures_filesystem(),
            Capability::MemorySnapshot => self.snapshot.captures_memory(),
            Capability::Fork => self.fork,
            Capability::PauseResume => self.pause_resume,
            Capability::PortForward => self.port_forward,
        }
    }

    /// Check that `capability` is available before relying on it.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Unsupported`] naming `sandbox` and `capability` when
    /// this set does not include it.
    pub fn require(&self, sandbox: &str, capability: Capability) -> Result<()> {
        if self.supports(capability) {
            return Ok(());
        }
        Err(Error::Unsupported {
            sandbox: sandbox.to_owned(),
            capability,
        })
    }

    /// Whether this sandbox is strong enough to run code the operator does not
    /// trust.
    ///
    /// [`IsolationLevel::Kernel`] is the floor: the guest must at least be
    /// unable to see or signal host processes.
    #[must_use]
    pub const fn is_suitable_for_untrusted_code(&self) -> bool {
        self.isolation.is_at_least(IsolationLevel::Kernel)
    }
}

#[cfg(test)]
mod test;
