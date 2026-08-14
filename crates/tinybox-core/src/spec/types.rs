//! The parts a [`BoxSpec`](crate::spec::BoxSpec) is assembled from.

use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::identity::{HostRef, SandboxRef, SnapshotId};

/// One machine-and-confinement pairing.
///
/// See the [module documentation](crate::spec) for why these two are separate
/// choices rather than a single backend enum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Placement {
    /// Which machine the process runs on.
    pub host: HostRef,
    /// What confines the process on that machine.
    pub sandbox: SandboxRef,
}

impl Placement {
    /// Pair a host with a sandbox.
    #[must_use]
    pub const fn new(host: HostRef, sandbox: SandboxRef) -> Self {
        Self { host, sandbox }
    }

    /// Whether `other` names the same machine, whatever confines it.
    ///
    /// Two placements sharing a host can exchange files directly instead of
    /// going through a sync, which is the main reason a caller asks.
    #[must_use]
    pub fn shares_host(&self, other: &Self) -> bool {
        self.host == other.host
    }
}

/// Where a workspace filesystem comes from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum WorkspaceSource {
    /// A directory on the host, mounted or synced into the box.
    LocalDir(PathBuf),
    /// An OCI image reference such as `alpine:3`.
    OciImage(String),
    /// A previously captured snapshot, which is also how templates are used.
    Snapshot(SnapshotId),
    /// A git repository cloned at a specific revision.
    GitRepo {
        /// The clone URL.
        url: String,
        /// The revision to check out — a branch, tag, or commit.
        rev: String,
    },
}

/// The limits applied to a workspace.
///
/// Every limit is positive; [`Resources::validate`] rejects zero because a zero
/// limit reads as "unlimited" to some backends and "deny everything" to others.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Resources {
    /// CPU allowance in thousandths of a core, so `1500` is one and a half.
    pub cpu_millis: u32,
    /// Maximum resident memory in bytes.
    pub memory_bytes: u64,
    /// Maximum number of processes and threads.
    pub pids_max: u32,
    /// Maximum writable filesystem size in bytes.
    pub disk_bytes: u64,
}

impl Resources {
    /// A modest default sized for an agent task rather than a build farm:
    /// two cores, 2 GiB of memory, 512 processes, and 8 GiB of disk.
    pub const DEFAULT: Self = Self {
        cpu_millis: 2_000,
        memory_bytes: 2 * 1024 * 1024 * 1024,
        pids_max: 512,
        disk_bytes: 8 * 1024 * 1024 * 1024,
    };

    /// Check that every limit is greater than zero.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ZeroResourceLimit`](crate::error::Error::ZeroResourceLimit) naming the first zero limit found,
    /// checked in declaration order.
    pub const fn validate(&self) -> Result<()> {
        if self.cpu_millis == 0 {
            return Err(Error::ZeroResourceLimit {
                limit: "cpu_millis",
            });
        }
        if self.memory_bytes == 0 {
            return Err(Error::ZeroResourceLimit {
                limit: "memory_bytes",
            });
        }
        if self.pids_max == 0 {
            return Err(Error::ZeroResourceLimit { limit: "pids_max" });
        }
        if self.disk_bytes == 0 {
            return Err(Error::ZeroResourceLimit {
                limit: "disk_bytes",
            });
        }
        Ok(())
    }
}

impl Default for Resources {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// How long a box lives, and whether it captures state as it runs.
///
/// Ephemeral and persistent boxes are policy over the same primitives, not
/// separate machinery: both create, exec, snapshot, and fork identically. Only
/// the reaper and the autosnapshot timer read this field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Lifecycle {
    /// Discarded once `ttl` elapses, with no snapshots taken on the way.
    ///
    /// This is the shape for untrusted agent code: disposable, served from a
    /// warm pool, and never resumed.
    Ephemeral {
        /// How long the box survives after creation.
        ttl: Duration,
    },
    /// Kept until explicitly destroyed, snapshotting on a cadence.
    ///
    /// This is the shape for a developer workspace: stopping captures state and
    /// archives it, and resuming forks the newest snapshot.
    Persistent {
        /// How often to snapshot while running, or `None` to snapshot only on
        /// stop.
        autosnapshot: Option<Duration>,
    },
}

impl Lifecycle {
    /// The default ephemeral lifetime: one hour.
    pub const DEFAULT_TTL: Duration = Duration::from_secs(60 * 60);

    /// The default autosnapshot cadence for persistent boxes: one minute.
    pub const DEFAULT_AUTOSNAPSHOT: Duration = Duration::from_secs(60);

    /// A persistent box snapshotting on the default cadence.
    #[must_use]
    pub const fn persistent() -> Self {
        Self::Persistent {
            autosnapshot: Some(Self::DEFAULT_AUTOSNAPSHOT),
        }
    }

    /// Whether this box should be snapshotted automatically, and how often.
    #[must_use]
    pub const fn autosnapshot_interval(&self) -> Option<Duration> {
        match self {
            Self::Ephemeral { .. } => None,
            Self::Persistent { autosnapshot } => *autosnapshot,
        }
    }

    /// Whether a reaper should destroy this box once its lifetime elapses.
    #[must_use]
    pub const fn is_ephemeral(&self) -> bool {
        matches!(self, Self::Ephemeral { .. })
    }
}

impl Default for Lifecycle {
    fn default() -> Self {
        Self::Ephemeral {
            ttl: Self::DEFAULT_TTL,
        }
    }
}

/// One published port: a guest port made reachable from the host.
///
/// Ports live on the spec rather than behind a handle because that is when they
/// can actually be applied — a container publishes ports at creation and cannot
/// gain one afterwards. Modelling them as a later operation would promise
/// something no backend can deliver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PortMapping {
    /// The port inside the box.
    pub guest: u16,
    /// The port on the host, or `None` to let the host choose a free one.
    pub host: Option<u16>,
}

impl PortMapping {
    /// Publish `guest` on an automatically chosen host port.
    #[must_use]
    pub const fn dynamic(guest: u16) -> Self {
        Self { guest, host: None }
    }

    /// Publish `guest` on exactly `host`.
    #[must_use]
    pub const fn fixed(guest: u16, host: u16) -> Self {
        Self {
            guest,
            host: Some(host),
        }
    }
}

/// What a workspace may reach over the network.
///
/// The default is [`NetworkPolicy::Denied`] because the common case is running
/// code that has no business making outbound connections, and an accidental
/// default of "open" is the kind of mistake that is only noticed afterwards.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub enum NetworkPolicy {
    /// No network access at all.
    #[default]
    Denied,
    /// Outbound connections permitted; inbound not published.
    Egress,
    /// Unrestricted, sharing the host's network view.
    Open,
}

impl NetworkPolicy {
    /// Whether the workspace can open outbound connections.
    #[must_use]
    pub const fn allows_egress(self) -> bool {
        matches!(self, Self::Egress | Self::Open)
    }
}
