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

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

mod types;

pub use types::{
    EgressAllowlist, Lifecycle, NetworkPolicy, Placement, PortMapping, Resources, Retention,
    WorkspaceSource,
};

/// The complete description of a box, before any sandbox acts on it.
///
/// A spec is inert data: it says what is wanted, never how to build it. That
/// keeps it serializable, comparable, and safe to store as part of a snapshot
/// manifest or a template.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    /// Constraints the caller requires the selected sandbox to enforce fully.
    ///
    /// Resource values remain soft defaults unless their corresponding
    /// constraint is listed here. Defaulted on read for stored specs created
    /// before hard requirements were introduced.
    #[serde(default)]
    pub hard_requirements: Vec<crate::Constraint>,
    /// How long the box lives and whether it snapshots as it goes.
    pub lifecycle: Lifecycle,
    /// What the workspace may reach over the network.
    pub network: NetworkPolicy,
    /// Guest ports published to the host.
    ///
    /// Ordered and deduplicated, so two specs differing only in the order the
    /// ports were named compare equal — which keeps template identity stable.
    ///
    /// Defaulted on read: a store written before ports existed must still load,
    /// or upgrading tinybox would orphan every box already recorded in it.
    #[serde(default)]
    pub ports: BTreeSet<PortMapping>,
    /// Environment variables set for every command in the workspace.
    ///
    /// Ordered so that two specs differing only in insertion order compare
    /// equal, which keeps template and snapshot identity stable.
    pub env: BTreeMap<String, String>,
    /// Keep the box for its owner between uses, or `None` for an ordinary box.
    ///
    /// Defaulted on read: a store written before retention existed must still
    /// load, and its boxes were never retained.
    #[serde(default)]
    pub retention: Option<Retention>,
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
            hard_requirements: Vec::new(),
            lifecycle: Lifecycle::default(),
            network: NetworkPolicy::default(),
            ports: BTreeSet::new(),
            env: BTreeMap::new(),
            retention: None,
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

    /// Replace the workspace source.
    ///
    /// This is what forking uses: the snapshot becomes the filesystem the new
    /// box starts from, and everything else about the spec is carried over.
    #[must_use]
    pub fn with_source(mut self, source: WorkspaceSource) -> Self {
        self.source = source;
        self
    }

    /// Replace the resource limits.
    #[must_use]
    pub const fn with_resources(mut self, resources: Resources) -> Self {
        self.resources = resources;
        self
    }

    /// Require the selected sandbox to fully enforce each listed constraint.
    #[must_use]
    pub fn with_hard_requirements(
        mut self,
        requirements: impl IntoIterator<Item = crate::Constraint>,
    ) -> Self {
        self.hard_requirements = requirements.into_iter().collect();
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
    pub fn with_network(mut self, network: NetworkPolicy) -> Self {
        self.network = network;
        self
    }

    /// Publish one guest port to the host.
    #[must_use]
    pub fn with_port(mut self, port: PortMapping) -> Self {
        self.ports.insert(port);
        self
    }

    /// Set one environment variable, replacing any previous value for the key.
    #[must_use]
    pub fn with_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.insert(key.into(), value.into());
        self
    }

    /// Keep the box for its owner between uses.
    ///
    /// Only a sandbox that declares [`Capability::Retention`](crate::Capability::Retention)
    /// accepts the spec; every other sandbox refuses it.
    #[must_use]
    pub fn with_retention(mut self, retention: Retention) -> Self {
        self.retention = Some(retention);
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
    /// naming the first limit that is zero, or
    /// [`Error::InvalidNetworkPolicy`](crate::error::Error::InvalidNetworkPolicy)
    /// for a malformed network allowlist, or whatever [`Retention::validate`]
    /// refuses.
    pub fn validate(&self) -> crate::Result<()> {
        self.resources.validate()?;
        self.network.validate()?;
        self.retention.as_ref().map_or(Ok(()), Retention::validate)
    }

    /// Refuse a retention request on a sandbox that cannot honour it.
    ///
    /// Every sandbox except one declaring
    /// [`Capability::Retention`](crate::Capability::Retention) calls this from
    /// `create`, so a retained box is never quietly run as a disposable one.
    ///
    /// # Errors
    ///
    /// [`Error::Unsupported`](crate::error::Error::Unsupported) naming
    /// [`Capability::Retention`](crate::Capability::Retention) when the spec
    /// carries a [`Retention`].
    pub fn refuse_retention(&self, sandbox: &str) -> crate::Result<()> {
        if self.retention.is_some() {
            return Err(crate::Error::Unsupported {
                sandbox: sandbox.to_owned(),
                capability: crate::Capability::Retention,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod test;
