//! The v2 storage body of a box record.
//!
//! [`BoxInfo`] and [`BoxSpec`] are model types: their serde form is shared with
//! templates and snapshot manifests, and it uses `Duration` and `SystemTime`
//! encodings and `PascalCase` variant names. The document body is its own type
//! so the stored shape follows the schema (`snake_case`, `*_ms` times, tagged
//! variants) without touching the model's wire form.
//!
//! The box id is the document id and is not repeated in the body.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tinybox_core::{
    BoxId, BoxInfo, BoxSpec, BoxState, EgressAllowlist, Error, Lifecycle, NetworkPolicy, Placement,
    PortMapping, Resources, Result, SnapshotId, WorkspaceSource,
};

/// One box as a `box.boxes` document body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct BoxRecord {
    pub(crate) state: StateRecord,
    pub(crate) spec: SpecRecord,
    /// When the box was created, if known (Unix epoch ms).
    ///
    /// This is not the document's `created_ms` metadata: the driver always
    /// stamps that, but a box recorded before tinybox tracked time has no
    /// creation time, and "unknown" must stay distinguishable from "now" or
    /// the reaper would treat a migrated box as brand new (or ancient).
    pub(crate) created_ms: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum StateRecord {
    Creating,
    Ready,
    Running,
    Paused,
    Stopped,
    Archived,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SpecRecord {
    runner: Placement,
    workspace: Placement,
    source: SourceRecord,
    resources: Resources,
    lifecycle: LifecycleRecord,
    network: NetworkRecord,
    #[serde(default)]
    hard_requirements: Vec<tinybox_core::Constraint>,
    ports: BTreeSet<PortMapping>,
    env: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum SourceRecord {
    LocalDir { path: PathBuf },
    OciImage { image: String },
    Snapshot { snapshot: SnapshotId },
    GitRepo { url: String, rev: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum LifecycleRecord {
    Ephemeral { ttl_ms: u64 },
    Persistent { autosnapshot_ms: Option<u64> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum NetworkRecord {
    Denied,
    Egress,
    Allowlist { hosts: Vec<String>, ports: Vec<u16> },
    Open,
}

fn unsupported(what: &str) -> Error {
    Error::Store {
        operation: "encode",
        message: format!("this version cannot store a {what} it does not know"),
    }
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn system_time_ms(at: SystemTime) -> i64 {
    match at.duration_since(UNIX_EPOCH) {
        Ok(after) => i64::try_from(after.as_millis()).unwrap_or(i64::MAX),
        Err(before) => i64::try_from(before.duration().as_millis()).map_or(i64::MIN, |ms| -ms),
    }
}

fn system_time_from_ms(ms: i64) -> SystemTime {
    let magnitude = Duration::from_millis(ms.unsigned_abs());
    if ms >= 0 {
        UNIX_EPOCH + magnitude
    } else {
        UNIX_EPOCH - magnitude
    }
}

impl TryFrom<&BoxInfo> for BoxRecord {
    type Error = Error;

    fn try_from(info: &BoxInfo) -> Result<Self> {
        Ok(Self {
            state: StateRecord::try_from(info.state)?,
            spec: SpecRecord::try_from(&info.spec)?,
            created_ms: info.created_at.map(system_time_ms),
        })
    }
}

impl BoxRecord {
    /// The model record for the box stored under `id`.
    pub(crate) fn into_info(self, id: BoxId) -> BoxInfo {
        let mut info = BoxInfo::new(id, self.state.into(), self.spec.into_spec());
        info.created_at = self.created_ms.map(system_time_from_ms);
        info
    }
}

impl TryFrom<BoxState> for StateRecord {
    type Error = Error;

    fn try_from(state: BoxState) -> Result<Self> {
        Ok(match state {
            BoxState::Creating => Self::Creating,
            BoxState::Ready => Self::Ready,
            BoxState::Running => Self::Running,
            BoxState::Paused => Self::Paused,
            BoxState::Stopped => Self::Stopped,
            BoxState::Archived => Self::Archived,
            BoxState::Failed => Self::Failed,
            _ => return Err(unsupported("box state")),
        })
    }
}

impl From<StateRecord> for BoxState {
    fn from(state: StateRecord) -> Self {
        match state {
            StateRecord::Creating => Self::Creating,
            StateRecord::Ready => Self::Ready,
            StateRecord::Running => Self::Running,
            StateRecord::Paused => Self::Paused,
            StateRecord::Stopped => Self::Stopped,
            StateRecord::Archived => Self::Archived,
            StateRecord::Failed => Self::Failed,
        }
    }
}

impl TryFrom<&BoxSpec> for SpecRecord {
    type Error = Error;

    fn try_from(spec: &BoxSpec) -> Result<Self> {
        Ok(Self {
            runner: spec.runner.clone(),
            workspace: spec.workspace.clone(),
            source: SourceRecord::try_from(&spec.source)?,
            resources: spec.resources,
            lifecycle: LifecycleRecord::try_from(&spec.lifecycle)?,
            network: NetworkRecord::try_from(&spec.network)?,
            hard_requirements: spec.hard_requirements.clone(),
            ports: spec.ports.clone(),
            env: spec.env.clone(),
        })
    }
}

impl SpecRecord {
    fn into_spec(self) -> BoxSpec {
        let mut spec = BoxSpec::new(self.workspace, self.source.into());
        spec.runner = self.runner;
        spec.resources = self.resources;
        spec.lifecycle = self.lifecycle.into();
        spec.network = self.network.into();
        spec.hard_requirements = self.hard_requirements;
        spec.ports = self.ports;
        spec.env = self.env;
        spec
    }
}

impl TryFrom<&WorkspaceSource> for SourceRecord {
    type Error = Error;

    fn try_from(source: &WorkspaceSource) -> Result<Self> {
        Ok(match source {
            WorkspaceSource::LocalDir(path) => Self::LocalDir { path: path.clone() },
            WorkspaceSource::OciImage(image) => Self::OciImage {
                image: image.clone(),
            },
            WorkspaceSource::Snapshot(snapshot) => Self::Snapshot {
                snapshot: snapshot.clone(),
            },
            WorkspaceSource::GitRepo { url, rev } => Self::GitRepo {
                url: url.clone(),
                rev: rev.clone(),
            },
            _ => return Err(unsupported("workspace source")),
        })
    }
}

impl From<SourceRecord> for WorkspaceSource {
    fn from(source: SourceRecord) -> Self {
        match source {
            SourceRecord::LocalDir { path } => Self::LocalDir(path),
            SourceRecord::OciImage { image } => Self::OciImage(image),
            SourceRecord::Snapshot { snapshot } => Self::Snapshot(snapshot),
            SourceRecord::GitRepo { url, rev } => Self::GitRepo { url, rev },
        }
    }
}

impl TryFrom<&Lifecycle> for LifecycleRecord {
    type Error = Error;

    fn try_from(lifecycle: &Lifecycle) -> Result<Self> {
        Ok(match lifecycle {
            Lifecycle::Ephemeral { ttl } => Self::Ephemeral {
                ttl_ms: millis(*ttl),
            },
            Lifecycle::Persistent { autosnapshot } => Self::Persistent {
                autosnapshot_ms: autosnapshot.map(millis),
            },
            _ => return Err(unsupported("lifecycle")),
        })
    }
}

impl From<LifecycleRecord> for Lifecycle {
    fn from(lifecycle: LifecycleRecord) -> Self {
        match lifecycle {
            LifecycleRecord::Ephemeral { ttl_ms } => Self::Ephemeral {
                ttl: Duration::from_millis(ttl_ms),
            },
            LifecycleRecord::Persistent { autosnapshot_ms } => Self::Persistent {
                autosnapshot: autosnapshot_ms.map(Duration::from_millis),
            },
        }
    }
}

impl TryFrom<&NetworkPolicy> for NetworkRecord {
    type Error = Error;

    fn try_from(network: &NetworkPolicy) -> Result<Self> {
        Ok(match network {
            NetworkPolicy::Denied => Self::Denied,
            NetworkPolicy::Egress => Self::Egress,
            NetworkPolicy::Allowlist(list) => Self::Allowlist {
                hosts: list.hosts.clone(),
                ports: list.ports.clone(),
            },
            NetworkPolicy::Open => Self::Open,
            _ => return Err(unsupported("network policy")),
        })
    }
}

impl From<NetworkRecord> for NetworkPolicy {
    fn from(network: NetworkRecord) -> Self {
        match network {
            NetworkRecord::Denied => Self::Denied,
            NetworkRecord::Egress => Self::Egress,
            NetworkRecord::Allowlist { hosts, ports } => {
                Self::Allowlist(EgressAllowlist::new(hosts, ports))
            }
            NetworkRecord::Open => Self::Open,
        }
    }
}

#[cfg(test)]
#[path = "record_tests.rs"]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests;
