//! The agent37 HTTP contract as **pure functions**: the JSON request bodies and
//! response views, how a [`BoxSpec`] maps onto a create body, how an
//! [`ExecRequest`] becomes a single shell command, and how agent37's instance
//! `status` maps onto a [`BoxState`]. Nothing here touches the network, so
//! every mapping and refusal is unit-testable without a live service — the same
//! property ADR 0004 buys `OpenShell`'s `args.rs`.
//!
//! # Matching agent37's real API
//!
//! The shapes and paths below follow the published API
//! (<https://www.agent37.com/docs/quickstart>):
//!
//! - `POST {api}/v1/instances` — create; returns `{ id, status, url }`.
//! - `POST {sandbox}/v1/instances/{id}/exec` — run one command; returns
//!   `{ exit_code, stdout, stderr, truncated }` with **plain** (not base64)
//!   output.
//! - `GET {api}/v1/instances` — list; `{ data: [ <instance>, … ] }`, newest
//!   first, with no filter parameters.
//! - `GET {api}/v1/instances/{id}` — inspect; `{ id, status, … }`; 404 = gone.
//! - `DELETE {api}/v1/instances/{id}` — delete; 2xx or 404 = deleted.
//!
//! agent37 **mints the instance id** on create, so the backend records the box
//! under that id (it is a valid tinybox [`BoxId`](tinybox_core::BoxId)) and
//! addresses exec, inspect and delete with it directly — there is no
//! client-derived name.
//!
//! agent37 runs a sandbox from a **template name**, not a raw OCI image, and
//! rejects inline image references with `400`. A custom image is registered as
//! a workspace template out of band and then referred to by name. tinybox has
//! no template concept, so the host passes the agent37 template name in the
//! [`WorkspaceSource::OciImage`] slot, and [`check_spec`] treats it as the
//! template name verbatim.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use tinybox_core::{
    BoxSpec, BoxState, Capability, Constraint, Enforcement, Error, ExecOutput, ExecRequest,
    NetworkPolicy, Resources, Result, WorkspaceSource,
};

use crate::NAME;

/// One gibibyte, used to convert tinybox byte limits to agent37's whole-GB unit.
const GIBIBYTE: u64 = 1024 * 1024 * 1024;

/// agent37's offered `(vCPU, memory-GB)` instance shapes, smallest first. CPU is
/// only ever 2 or 4, and memory is coupled to it (2 vCPU pairs only with 4 GB);
/// any other combination returns `400 invalid_request`, so a request is snapped
/// to the smallest shape that covers it. Disk follows the shape, so it is not
/// set per box. (Free workspaces run only the first shape until a top-up; the
/// larger shapes then return `403 tier_limit`.)
const SHAPES: [(u32, u64); 4] = [(2, 4), (4, 8), (4, 16), (4, 32)];

/// Metadata key carrying the tinybox namespace on the agent37 instance. agent37
/// stores metadata and never interprets it; this is for observability only.
pub const NAMESPACE_METADATA_KEY: &str = "tinybox.namespace";

/// Metadata key carrying a retained box's owner key (see
/// [`Retention::key`](tinybox_core::Retention::key)). agent37 echoes metadata
/// back on list, which is how a box is found again after the host restarts.
/// Instances without this key are never touched by the retention pass.
pub const KEY_METADATA_KEY: &str = "tinybox.key";

/// The shortest idle timeout agent37 accepts, in seconds.
pub const MIN_IDLE_TIMEOUT_SECS: u32 = 300;

/// The longest idle timeout agent37 accepts, in seconds.
pub const MAX_IDLE_TIMEOUT_SECS: u32 = 86_400;

/// The CPU, memory and disk shape for an agent37 instance. All optional: an
/// omitted field takes agent37's template default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InstanceResources {
    /// Whole vCPUs, 1 to 4 (agent37's ceiling).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu: Option<u32>,
    /// Memory in whole gibibytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory: Option<u64>,
    /// Disk in whole gibibytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk: Option<u64>,
}

/// agent37's `network` policy. This backend supports only [`Network::DenyAll`];
/// widening egress is a service-side decision it will not silently assert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Network {
    /// No outbound network, DNS included.
    DenyAll,
}

/// `POST /v1/instances` body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CreateBody {
    /// The agent37 template name to run (see the module docs).
    pub template: String,
    /// The instance shape, or agent37's default when `None`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resources: Option<InstanceResources>,
    /// Egress policy; always [`Network::DenyAll`] for this backend.
    pub network: Network,
    /// Container environment, seeded from the box's env.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
    /// Workspace-defined key/value pairs; carries the namespace.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
    /// Put the instance to sleep when idle. Sent only for a retained box, so
    /// every other create serializes exactly as it always has.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_sleep: Option<bool>,
    /// Seconds idle before the instance sleeps, clamped to
    /// [`MIN_IDLE_TIMEOUT_SECS`]`..=`[`MAX_IDLE_TIMEOUT_SECS`]. Sent with
    /// `auto_sleep`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idle_timeout_seconds: Option<u32>,
}

/// `POST /v1/instances/{id}/exec` body.
///
/// agent37 runs `command` through `sh -c`, so the box's argv, working
/// directory, env and stdin are composed into this one string by
/// [`shell_command`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExecBody {
    /// The shell command line, run via `sh -c`.
    pub command: String,
}

/// `POST …/exec` response. Output is plain text, not base64.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ExecResult {
    /// The process exit status; non-zero is a result, not an error.
    pub exit_code: i32,
    /// Standard output (agent37 caps each stream at 512 KB).
    pub stdout: String,
    /// Standard error.
    pub stderr: String,
    /// Whether either stream spilled past agent37's cap.
    #[serde(default)]
    pub truncated: bool,
}

/// An instance as create, inspect, list and fork report it. Only the fields
/// this backend reads are named; the rest of the object is ignored.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct InstanceView {
    /// The agent37-minted instance id, used as the tinybox box id.
    pub id: String,
    /// The lifecycle status string (see [`box_state_from_status`]).
    pub status: String,
    /// The free key/value metadata the instance was created with, echoed back
    /// and never interpreted by agent37. Values are kept as JSON because the
    /// workspace is shared: another tenant's instance may hold a non-string,
    /// and that must not fail a whole listing.
    #[serde(default)]
    pub metadata: Option<BTreeMap<String, serde_json::Value>>,
    /// When the instance was created, in unix seconds, when reported.
    #[serde(default)]
    pub created: Option<u64>,
    /// When the instance fell asleep, in unix seconds; set only while it
    /// sleeps.
    #[serde(default)]
    pub slept_at: Option<u64>,
}

impl InstanceView {
    /// A view with only an id and a status, as create and inspect minimally
    /// report one; the lifecycle fields are unset.
    #[must_use]
    pub fn new(id: impl Into<String>, status: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            status: status.into(),
            metadata: None,
            created: None,
            slept_at: None,
        }
    }

    /// Whether the instance carries a [`KEY_METADATA_KEY`] entry, whatever its
    /// value: it was made by a retaining tinybox, so the retention pass may
    /// expire it.
    #[must_use]
    pub fn has_retention_key(&self) -> bool {
        self.metadata
            .as_ref()
            .is_some_and(|metadata| metadata.contains_key(KEY_METADATA_KEY))
    }

    /// The owner key this instance was created for, when it has a string one.
    #[must_use]
    pub fn retention_key(&self) -> Option<&str> {
        self.metadata
            .as_ref()?
            .get(KEY_METADATA_KEY)?
            .as_str()
    }

    /// The tinybox state this instance's status maps to.
    #[must_use]
    pub fn state(&self) -> BoxState {
        box_state_from_status(&self.status)
    }

    /// Whether the status is exactly `sleeping`.
    #[must_use]
    pub fn is_sleeping(&self) -> bool {
        self.status.eq_ignore_ascii_case("sleeping")
    }
}

/// `GET /v1/instances` response.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ListResponse {
    /// Every instance in the workspace, newest first.
    pub data: Vec<InstanceView>,
}

/// The template a spec asks for, or the reason this backend refuses it.
///
/// The returned string is the agent37 template name taken from the
/// [`WorkspaceSource::OciImage`] slot (see the module docs).
///
/// # Errors
///
/// - [`Error::UnsupportedWorkspaceSource`] for anything but an OCI-image slot.
/// - [`Error::ConstraintNotEnforced`] for a network policy other than
///   [`NetworkPolicy::Denied`].
/// - [`Error::Unsupported`] when the spec publishes ports.
pub fn check_spec(spec: &BoxSpec) -> Result<String> {
    let template = match &spec.source {
        WorkspaceSource::OciImage(reference) => reference.clone(),
        WorkspaceSource::LocalDir(_) => return Err(unsupported_source("local directory")),
        WorkspaceSource::Snapshot(_) => return Err(unsupported_source("snapshot")),
        WorkspaceSource::GitRepo { .. } => return Err(unsupported_source("git repository")),
        _ => return Err(unsupported_source("unknown")),
    };
    if spec.network != NetworkPolicy::Denied {
        return Err(Error::ConstraintNotEnforced {
            sandbox: NAME.to_owned(),
            constraint: Constraint::Network,
            enforcement: Enforcement::Unsupported,
        });
    }
    if !spec.ports.is_empty() {
        return Err(Error::Unsupported {
            sandbox: NAME.to_owned(),
            capability: Capability::PortForward,
        });
    }
    Ok(template)
}

fn unsupported_source(kind: &'static str) -> Error {
    Error::UnsupportedWorkspaceSource {
        sandbox: NAME.to_owned(),
        kind,
    }
}

/// Snap tinybox resource limits onto one of agent37's offered `SHAPES`, or
/// `None` when the spec sets neither CPU nor memory (so agent37 uses the
/// template default).
///
/// The result is the smallest shape whose vCPU and memory both cover the
/// request (CPU rounded up to a whole core and capped at agent37's ceiling of
/// 4, memory rounded up to whole GB); a request larger than every shape snaps
/// to the largest. This keeps a create from failing with
/// `400 invalid_request` on a shape agent37 does not offer, at the cost of
/// giving at least what was asked for rather than exactly it — hence the
/// [`Enforcement::BestEffort`] declaration. Disk is left to the shape default.
#[must_use]
pub fn instance_resources(resources: &Resources) -> Option<InstanceResources> {
    if resources.cpu_millis == 0 && resources.memory_bytes == 0 {
        return None;
    }
    let want_cpu = resources.cpu_millis.div_ceil(1000).clamp(1, 4);
    let want_memory = resources.memory_bytes.div_ceil(GIBIBYTE).max(1);
    let (cpu, memory) = SHAPES
        .iter()
        .copied()
        .find(|&(cpu, memory)| cpu >= want_cpu && memory >= want_memory)
        .unwrap_or(SHAPES[SHAPES.len() - 1]);
    Some(InstanceResources {
        cpu: Some(cpu),
        memory: Some(memory),
        disk: None,
    })
}

/// Build the create body for `spec` under `namespace`.
///
/// A spec with [`Retention`](tinybox_core::Retention) also turns on agent37's
/// auto-sleep and stamps the owner key into the metadata; without one the body
/// carries neither.
///
/// # Errors
///
/// Everything [`check_spec`] refuses.
pub fn create_body(namespace: &str, spec: &BoxSpec) -> Result<CreateBody> {
    let template = check_spec(spec)?;
    let mut metadata = BTreeMap::from([(NAMESPACE_METADATA_KEY.to_owned(), namespace.to_owned())]);
    let (auto_sleep, idle_timeout_seconds) = match &spec.retention {
        Some(retention) => {
            metadata.insert(KEY_METADATA_KEY.to_owned(), retention.key.clone());
            (
                Some(true),
                Some(
                    retention
                        .idle_sleep_secs
                        .clamp(MIN_IDLE_TIMEOUT_SECS, MAX_IDLE_TIMEOUT_SECS),
                ),
            )
        }
        None => (None, None),
    };
    Ok(CreateBody {
        template,
        resources: instance_resources(&spec.resources),
        network: Network::DenyAll,
        env: spec.env.clone(),
        metadata,
        auto_sleep,
        idle_timeout_seconds,
    })
}

/// Build the exec body for a command.
#[must_use]
pub fn exec_body(request: &ExecRequest) -> ExecBody {
    ExecBody {
        command: shell_command(request),
    }
}

/// Compose a box's argv, working directory, env and stdin into one `sh -c`
/// command line, which is all agent37's exec accepts.
///
/// Every value is single-quoted so a space, quote or metacharacter in a path,
/// argument or variable cannot break out of its slot. Stdin, when present, is
/// base64-encoded and decoded inside the instance, then piped in, so arbitrary
/// bytes survive both JSON and the shell.
#[must_use]
pub fn shell_command(request: &ExecRequest) -> String {
    use base64::Engine as _;

    let mut inner = String::new();
    if let Some(cwd) = &request.cwd {
        inner.push_str("cd ");
        inner.push_str(&single_quote(&cwd.to_string_lossy()));
        inner.push_str(" && ");
    }
    for (key, value) in &request.env {
        // `KEY=value` prefixes set the variable for the command that follows.
        inner.push_str(key);
        inner.push('=');
        inner.push_str(&single_quote(value));
        inner.push(' ');
    }
    inner.push_str(
        &request
            .argv
            .iter()
            .map(|arg| single_quote(arg))
            .collect::<Vec<_>>()
            .join(" "),
    );

    match &request.stdin {
        Some(bytes) => {
            let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
            // Feed stdin by decoding it inside the instance and piping it into a
            // subshell that runs the composed command, so cwd and env still apply.
            format!(
                "printf %s {} | base64 -d | ( {inner} )",
                single_quote(&encoded)
            )
        }
        None => inner,
    }
}

/// Single-quote a string for POSIX `sh`, escaping embedded single quotes as the
/// standard `'\''` sequence.
fn single_quote(value: &str) -> String {
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('\'');
    for character in value.chars() {
        if character == '\'' {
            quoted.push_str("'\\''");
        } else {
            quoted.push(character);
        }
    }
    quoted.push('\'');
    quoted
}

/// Turn an exec response into an [`ExecOutput`]. Output is plain text, so the
/// bytes are taken as-is; a non-zero exit is a result, not an error.
#[must_use]
pub fn exec_output(result: &ExecResult) -> ExecOutput {
    ExecOutput::new(
        result.exit_code,
        result.stdout.clone().into_bytes(),
        result.stderr.clone().into_bytes(),
    )
}

/// Map an agent37 instance `status` onto a tinybox [`BoxState`].
///
/// `sleeping` maps to [`BoxState::Ready`] because an exec request wakes a
/// sleeping instance, so it still accepts commands. An unknown status maps to
/// [`BoxState::Failed`] rather than being guessed into a usable state (tinybox
/// rule 1: never report "contained" without proof).
#[must_use]
pub fn box_state_from_status(status: &str) -> BoxState {
    match status.to_ascii_lowercase().as_str() {
        "provisioning" | "creating" | "starting" | "waking" => BoxState::Creating,
        "running" | "ready" | "sleeping" => BoxState::Ready,
        "stopped" => BoxState::Stopped,
        "deleted" | "gone" | "archived" => BoxState::Archived,
        _ => BoxState::Failed,
    }
}

#[cfg(test)]
#[path = "api_tests.rs"]
mod tests;
