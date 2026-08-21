//! What a sandbox can actually do, and how a caller is told when it cannot.
//!
//! Every [`Sandbox`](crate::runtime::Sandbox) declares a
//! [`SandboxCapabilities`] describing its real behavior. Core code checks the
//! declaration before dispatching and returns [`Error::Unsupported`] rather
//! than emulating a capability badly.
//!
//! This matters most at the weak end of the range. A passthrough sandbox runs
//! a bare host process with no confinement whatsoever; if it reported the same
//! shape as a microVM, callers would believe untrusted code had been contained
//! when it had not. Declaring [`IsolationLevel::None`] keeps that honest, and
//! so does declining [`Capability::ResourceLimits`] — a sandbox that cannot cap
//! memory should say so rather than accept a limit it will never apply.
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
/// Build one from [`SandboxCapabilities::new`] and add what the backend
/// supports:
///
/// ```
/// use tinybox_core::capability::{IsolationLevel, SandboxCapabilities, SnapshotSupport};
///
/// use tinybox_core::capability::Capability;
///
/// let docker = SandboxCapabilities::new(IsolationLevel::Kernel, SnapshotSupport::Filesystem)
///     .with_fork()
///     .with_port_forward()
///     .with_resource_limits();
///
/// assert!(docker.is_suitable_for_untrusted_code());
/// assert!(docker.supports(Capability::Fork));
/// assert!(!docker.supports(Capability::PauseResume));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct SandboxCapabilities {
    /// How strongly the sandbox separates guest code from the host.
    pub isolation: IsolationLevel,
    /// What the sandbox can capture and restore.
    pub snapshot: SnapshotSupport,
    /// The remaining behaviors, held as a set rather than a row of booleans so
    /// that [`SandboxCapabilities::supports`] is the single way to ask.
    features: u8,
}

impl SandboxCapabilities {
    /// A bare host process: reach without confinement.
    ///
    /// Useful for trusted local development, and never for untrusted code.
    pub const PASSTHROUGH: Self = Self::new(IsolationLevel::None, SnapshotSupport::None);

    /// Declare a sandbox that isolates to `isolation` and snapshots to
    /// `snapshot`, supporting nothing else.
    ///
    /// Add the rest with the `with_*` methods, so each capability is named at
    /// the call site instead of being a positional boolean.
    #[must_use]
    pub const fn new(isolation: IsolationLevel, snapshot: SnapshotSupport) -> Self {
        Self {
            isolation,
            snapshot,
            features: 0,
        }
    }

    /// Declare that snapshots can be branched into independent boxes.
    #[must_use]
    pub const fn with_fork(self) -> Self {
        self.with(Capability::Fork)
    }

    /// Declare that a running box can be frozen and thawed.
    #[must_use]
    pub const fn with_pause_resume(self) -> Self {
        self.with(Capability::PauseResume)
    }

    /// Declare that guest ports can be published to the host.
    #[must_use]
    pub const fn with_port_forward(self) -> Self {
        self.with(Capability::PortForward)
    }

    /// Declare that the limits in [`Resources`](crate::spec::Resources) are
    /// actually applied.
    ///
    /// A sandbox that ignores them must not call this. Accepting a memory cap
    /// and never enforcing it is the same class of dishonesty as reporting
    /// isolation that does not exist.
    #[must_use]
    pub const fn with_resource_limits(self) -> Self {
        self.with(Capability::ResourceLimits)
    }

    /// Declare that a process can be left running in a box and found again.
    ///
    /// See [`Capability::Detach`] for what a backend is promising. A sandbox
    /// that cannot later locate or stop such a process must not call this.
    #[must_use]
    pub const fn with_detach(self) -> Self {
        self.with(Capability::Detach)
    }

    /// Add one capability to the set.
    ///
    /// Snapshot capabilities are not settable this way: what a sandbox can
    /// capture is [`SandboxCapabilities::snapshot`], and having two ways to say
    /// it would let them disagree.
    #[must_use]
    const fn with(mut self, capability: Capability) -> Self {
        self.features |= capability.bit();
        self
    }

    /// Every capability this sandbox declares, in a stable order.
    ///
    /// Useful for reporting; [`SandboxCapabilities::supports`] is the way to
    /// ask about one.
    #[must_use]
    pub fn declared(&self) -> Vec<Capability> {
        Capability::ALL
            .into_iter()
            .filter(|capability| self.supports(*capability))
            .collect()
    }

    /// Whether this set includes `capability`.
    #[must_use]
    pub const fn supports(&self, capability: Capability) -> bool {
        match capability {
            // Snapshot support is described by its own field, so it is answered
            // from there rather than duplicated into the set.
            Capability::FilesystemSnapshot => self.snapshot.captures_filesystem(),
            Capability::MemorySnapshot => self.snapshot.captures_memory(),
            other => self.features & other.bit() != 0,
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
