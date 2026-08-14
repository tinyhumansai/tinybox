//! What a box is: where it runs, what code it holds, and what it may consume.
//!
//! # Why reach and confinement are separate
//!
//! SSH answers *which machine* a process runs on. Docker answers *what
//! confines it*. They are different questions, so tinybox models them as two
//! independent choices joined by a [`Placement`]:
//!
//! ```text
//! Host — reach                     Sandbox — confinement
//! ├─ local                         ├─ passthrough
//! └─ ssh                           ├─ docker
//!                                  ├─ namespace
//!                                  └─ microvm
//! ```
//!
//! Composition then costs nothing: `ssh` + `docker` is Docker on a remote
//! machine without a line of code dedicated to that pairing. Folding the two
//! axes into one enum would instead require a variant per combination.
//!
//! # Why a box names two placements
//!
//! The runner — the tinybox agent driving the work — and the workspace — where
//! the user's code actually executes — need not sit in the same place. A local
//! runner can drive a remote workspace, or a containerized runner can drive a
//! microVM workspace. [`BoxSpec::runner`] and [`BoxSpec::workspace`] are
//! therefore independent; [`BoxSpec::new`] colocates them for the common case,
//! and [`BoxSpec::with_runner`] splits them apart.
//!
//! ```
//! use tinybox_core::identity::{HostRef, SandboxRef};
//! use tinybox_core::spec::{BoxSpec, Placement, WorkspaceSource};
//!
//! let local = Placement::new(HostRef::new("local")?, SandboxRef::new("docker")?);
//! let spec = BoxSpec::new(local, WorkspaceSource::OciImage("alpine:3".into()));
//!
//! assert_eq!(spec.runner, spec.workspace);
//! # Ok::<(), tinybox_core::Error>(())
//! ```

use std::collections::BTreeMap;

mod types;

pub use types::{Lifecycle, NetworkPolicy, Placement, Resources, WorkspaceSource};

/// The complete description of a box, before any sandbox acts on it.
///
/// A spec is inert data: it says what is wanted, never how to build it. That
/// keeps it serializable, comparable, and safe to store as part of a snapshot
/// manifest or a template.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct BoxSpec {
    /// Where the tinybox agent driving this box runs.
    pub runner: Placement,
    /// Where the user's code runs. Often equal to [`BoxSpec::runner`].
    pub workspace: Placement,
    /// What the workspace filesystem is populated from.
    pub source: WorkspaceSource,
    /// The limits applied to the workspace.
    pub resources: Resources,
    /// How long the box lives and whether it snapshots as it goes.
    pub lifecycle: Lifecycle,
    /// What the workspace may reach over the network.
    pub network: NetworkPolicy,
    /// Environment variables set for every command in the workspace.
    ///
    /// Ordered so that two specs differing only in insertion order compare
    /// equal, which keeps template and snapshot identity stable.
    pub env: BTreeMap<String, String>,
}

impl BoxSpec {
    /// Describe a box that runs its agent and its code in the same place.
    ///
    /// Applies [`Resources::DEFAULT`], [`Lifecycle::default`], and
    /// [`NetworkPolicy::default`]; use the `with_*` methods to depart from
    /// those.
    #[must_use]
    pub fn new(placement: Placement, source: WorkspaceSource) -> Self {
        Self {
            runner: placement.clone(),
            workspace: placement,
            source,
            resources: Resources::DEFAULT,
            lifecycle: Lifecycle::default(),
            network: NetworkPolicy::default(),
            env: BTreeMap::new(),
        }
    }

    /// Split the runner away from the workspace.
    ///
    /// This is the "local runner, remote workspace" case, and the reason
    /// [`BoxSpec`] carries two placements rather than one.
    #[must_use]
    pub fn with_runner(mut self, runner: Placement) -> Self {
        self.runner = runner;
        self
    }

    /// Replace the resource limits.
    #[must_use]
    pub const fn with_resources(mut self, resources: Resources) -> Self {
        self.resources = resources;
        self
    }

    /// Replace the lifecycle policy.
    #[must_use]
    pub fn with_lifecycle(mut self, lifecycle: Lifecycle) -> Self {
        self.lifecycle = lifecycle;
        self
    }

    /// Replace the network policy.
    #[must_use]
    pub const fn with_network(mut self, network: NetworkPolicy) -> Self {
        self.network = network;
        self
    }

    /// Set one environment variable, replacing any previous value for the key.
    #[must_use]
    pub fn with_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.insert(key.into(), value.into());
        self
    }

    /// Whether the agent and the workload share a placement.
    #[must_use]
    pub fn is_colocated(&self) -> bool {
        self.runner == self.workspace
    }

    /// Check that every resource limit is usable.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ZeroResourceLimit`](crate::error::Error::ZeroResourceLimit)
    /// naming the first limit that is zero.
    pub fn validate(&self) -> crate::Result<()> {
        self.resources.validate()
    }
}

#[cfg(test)]
mod test;
