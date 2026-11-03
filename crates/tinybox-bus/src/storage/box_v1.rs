//! A v1 box row (a serialized `BoxInfo`) as the v2 `box.boxes` body.
//!
//! v1 stored the model's own serde form: `PascalCase` variants, externally
//! tagged enums, `Duration` as `{secs, nanos}` and `SystemTime` as
//! `{secs_since_epoch, nanos_since_epoch}`. The v2 body is `snake_case`, uses
//! internally tagged variants and one `*_ms` integer per instant. The
//! conversion is pure JSON to JSON.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct V1Box {
    id: String,
    state: V1State,
    spec: V1Spec,
    #[serde(default)]
    created_at: Option<V1Time>,
}

#[derive(Deserialize)]
enum V1State {
    Creating,
    Ready,
    Running,
    Paused,
    Stopped,
    Archived,
    Failed,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct V1Spec {
    runner: Value,
    workspace: Value,
    source: V1Source,
    resources: Value,
    lifecycle: V1Lifecycle,
    network: V1Network,
    #[serde(default)]
    hard_requirements: Vec<Value>,
    #[serde(default)]
    ports: Vec<Value>,
    env: BTreeMap<String, String>,
}

#[derive(Deserialize)]
enum V1Source {
    LocalDir(PathBuf),
    OciImage(String),
    Snapshot(String),
    GitRepo { url: String, rev: String },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct V1Duration {
    secs: u64,
    nanos: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct V1Time {
    secs_since_epoch: u64,
    nanos_since_epoch: u32,
}

#[derive(Deserialize)]
enum V1Lifecycle {
    Ephemeral {
        ttl: V1Duration,
    },
    Persistent {
        #[serde(default)]
        autosnapshot: Option<V1Duration>,
    },
}

#[derive(Deserialize)]
enum V1Network {
    Denied,
    Egress,
    Allowlist { hosts: Vec<String>, ports: Vec<u16> },
    Open,
}

fn duration_ms(duration: &V1Duration) -> u64 {
    duration
        .secs
        .saturating_mul(1000)
        .saturating_add(u64::from(duration.nanos / 1_000_000))
}

fn time_ms(time: &V1Time) -> i64 {
    let ms = duration_ms(&V1Duration {
        secs: time.secs_since_epoch,
        nanos: time.nanos_since_epoch,
    });
    i64::try_from(ms).unwrap_or(i64::MAX)
}

const fn state_name(state: &V1State) -> &'static str {
    match state {
        V1State::Creating => "creating",
        V1State::Ready => "ready",
        V1State::Running => "running",
        V1State::Paused => "paused",
        V1State::Stopped => "stopped",
        V1State::Archived => "archived",
        V1State::Failed => "failed",
    }
}

fn source_body(source: V1Source) -> Value {
    match source {
        V1Source::LocalDir(path) => json!({"kind": "local_dir", "path": path}),
        V1Source::OciImage(image) => json!({"kind": "oci_image", "image": image}),
        V1Source::Snapshot(snapshot) => json!({"kind": "snapshot", "snapshot": snapshot}),
        V1Source::GitRepo { url, rev } => json!({"kind": "git_repo", "url": url, "rev": rev}),
    }
}

fn lifecycle_body(lifecycle: &V1Lifecycle) -> Value {
    match lifecycle {
        V1Lifecycle::Ephemeral { ttl } => {
            json!({"kind": "ephemeral", "ttl_ms": duration_ms(ttl)})
        }
        V1Lifecycle::Persistent { autosnapshot } => json!({
            "kind": "persistent",
            "autosnapshot_ms": autosnapshot.as_ref().map(duration_ms),
        }),
    }
}

fn network_body(network: V1Network) -> Value {
    match network {
        V1Network::Denied => json!({"kind": "denied"}),
        V1Network::Egress => json!({"kind": "egress"}),
        V1Network::Allowlist { hosts, ports } => {
            json!({"kind": "allowlist", "hosts": hosts, "ports": ports})
        }
        V1Network::Open => json!({"kind": "open"}),
    }
}

/// The v2 body for a v1 box row.
///
/// The box id is the document id and is not part of the body. A box recorded
/// before tinybox tracked time has no `created_at`; its `created_ms` stays
/// `null` so "unknown" is never mistaken for "now".
///
/// # Errors
///
/// A message when the row is not a v1 box this version understands.
pub fn to_body(source: Value) -> Result<Value, String> {
    let old: V1Box = serde_json::from_value(source).map_err(|error| error.to_string())?;
    drop(old.id);
    let V1Box {
        state,
        created_at,
        spec,
        ..
    } = old;
    Ok(json!({
        "state": state_name(&state),
        "created_ms": created_at.as_ref().map(time_ms),
        "spec": {
            "runner": spec.runner,
            "workspace": spec.workspace,
            "source": source_body(spec.source),
            "resources": spec.resources,
            "lifecycle": lifecycle_body(&spec.lifecycle),
            "network": network_body(spec.network),
            "hard_requirements": spec.hard_requirements,
            "ports": spec.ports,
            "env": spec.env,
        },
    }))
}

#[cfg(test)]
#[path = "box_v1_tests.rs"]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests;
