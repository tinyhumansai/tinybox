//! Building the `docker` command lines, and reading what comes back.
//!
//! Every function here is pure. That is deliberate: argument construction is
//! where the interesting decisions live — which limits are applied, how a
//! workspace source becomes an image reference, what a snapshot digest turns
//! into — and keeping it separate from the process execution means all of it is
//! testable without a daemon.

use tinybox_core::{
    BoxId, BoxSpec, Error, ExecRequest, NetworkPolicy, Resources, Result, SnapshotId,
    WorkspaceSource,
};

use super::NAME;

/// The label every tinybox container carries, so a stray container can be
/// traced back to the tool that made it.
pub const OWNER_LABEL: &str = "ai.tinyhumans.tinybox";

/// Where a bind-mounted local directory appears inside the container.
pub const WORKSPACE_MOUNT: &str = "/workspace";

/// The prefix a [`SnapshotId`] carries, distinguishing it from a box id at a
/// glance and keeping it a valid tinybox identifier.
const SNAPSHOT_PREFIX: &str = "sha-";

/// How many hex characters of an image digest a snapshot identifier keeps.
///
/// Twelve is what Docker itself shows as a short id, and it is unambiguous in
/// any realistic image store while staying short enough to type.
const SNAPSHOT_DIGEST_LENGTH: usize = 12;

/// The container name for a box in `namespace`.
///
/// Box identifiers are unique within a [`Store`](tinybox_core::Store); Docker
/// container names are unique across a whole daemon. Those are different
/// scopes, so two stores that both allocate `box-0` would otherwise fight over
/// one container name. The namespace bridges them, and the `tinybox-` prefix
/// says on a shared machine where the container came from.
#[must_use]
pub fn container_name(namespace: &str, id: &BoxId) -> String {
    format!("tinybox-{namespace}-{id}")
}

/// The image reference a spec's source resolves to.
///
/// # Errors
///
/// Returns [`Error::UnsupportedWorkspaceSource`] for a git repository, which
/// needs a clone step this backend does not yet perform.
fn image_reference(spec: &BoxSpec) -> Result<String> {
    match &spec.source {
        WorkspaceSource::OciImage(reference) => Ok(reference.clone()),
        // A snapshot is a committed image, so it is already an image reference.
        WorkspaceSource::Snapshot(snapshot) => Ok(image_of_snapshot(snapshot)),
        // A local directory is bind-mounted into a base image rather than being
        // the image itself, so the caller supplies the base.
        WorkspaceSource::LocalDir(_) => Ok(DEFAULT_BASE_IMAGE.to_owned()),
        WorkspaceSource::GitRepo { .. } => Err(Error::UnsupportedWorkspaceSource {
            sandbox: NAME.to_owned(),
            kind: "git repository",
        }),
        // `WorkspaceSource` is non-exhaustive, so a source added to core after
        // this backend was written lands here. Refusing it is the only honest
        // answer: guessing at an image reference would produce a container
        // holding something other than what was asked for.
        _ => Err(Error::UnsupportedWorkspaceSource {
            sandbox: NAME.to_owned(),
            kind: "workspace source this backend does not recognize",
        }),
    }
}

/// The image a bind-mounted workspace runs in when the caller names no other.
///
/// Alpine is small and ships a shell, which the keepalive command needs.
pub const DEFAULT_BASE_IMAGE: &str = "alpine:3";

/// Keep the container alive so commands have somewhere to land.
///
/// A container exits as soon as its entrypoint returns, and an exited container
/// cannot be `docker exec`-ed into. Sleeping in a loop is the standard way to
/// hold one open.
///
/// This requires a shell in the image, which every mainstream base image has and
/// a distroless image does not — a real constraint, documented on the sandbox
/// itself rather than discovered at runtime.
const KEEPALIVE: [&str; 3] = ["sh", "-c", "while :; do sleep 86400; done"];

/// The `docker run` command that creates and starts a box.
///
/// # Errors
///
/// Returns [`Error::UnsupportedWorkspaceSource`] when the spec names a source
/// this backend cannot turn into a container.
pub(super) fn run(namespace: &str, id: &BoxId, spec: &BoxSpec) -> Result<Vec<String>> {
    let mut argv = vec![
        "docker".to_owned(),
        "run".to_owned(),
        "--detach".to_owned(),
        "--name".to_owned(),
        container_name(namespace, id),
        "--label".to_owned(),
        format!("{OWNER_LABEL}={id}"),
    ];

    argv.extend(resource_flags(&spec.resources));
    argv.extend(network_flags(spec.network));
    argv.extend(port_flags(spec));

    if let WorkspaceSource::LocalDir(path) = &spec.source {
        argv.push("--volume".to_owned());
        argv.push(format!("{}:{WORKSPACE_MOUNT}", path.display()));
        argv.push("--workdir".to_owned());
        argv.push(WORKSPACE_MOUNT.to_owned());
    }

    for (key, value) in &spec.env {
        argv.push("--env".to_owned());
        argv.push(format!("{key}={value}"));
    }

    argv.push(image_reference(spec)?);
    argv.extend(KEEPALIVE.iter().map(|part| (*part).to_owned()));
    Ok(argv)
}

/// Translate resource limits into the flags Docker enforces.
///
/// Docker takes CPU as a fractional core count, so thousandths convert
/// directly. Memory and disk are byte counts; `--storage-opt size=` is not
/// applied because it only works on a minority of storage drivers, and a flag
/// that silently does nothing on most systems is worse than an honest omission
/// — [`SandboxCapabilities`](tinybox_core::SandboxCapabilities) still declares
/// resource limits because CPU, memory, and process count *are* enforced.
fn resource_flags(resources: &Resources) -> Vec<String> {
    let cpus = f64::from(resources.cpu_millis) / 1000.0;
    vec![
        "--memory".to_owned(),
        format!("{}b", resources.memory_bytes),
        "--cpus".to_owned(),
        format!("{cpus}"),
        "--pids-limit".to_owned(),
        resources.pids_max.to_string(),
    ]
}

/// Translate the network policy into Docker's networking flags.
///
/// Docker has no "outbound only" network mode, so `Egress` gets the default
/// bridge — outbound works, and nothing is published inbound because tinybox
/// never passes `--publish`.
fn network_flags(policy: NetworkPolicy) -> Vec<String> {
    match policy {
        NetworkPolicy::Egress | NetworkPolicy::Open => Vec::new(),
        // `Denied`, and anything added to the non-exhaustive enum later. An
        // unrecognized policy must fail closed: granting network access to a
        // policy this backend does not understand is the one mistake here that
        // cannot be walked back.
        _ => vec!["--network".to_owned(), "none".to_owned()],
    }
}

/// Publish the spec's ports.
///
/// Nothing is published when the network is denied: a container with no network
/// has nowhere for a published port to lead, and Docker refuses the
/// combination outright. Dropping the flags rather than failing keeps
/// `NetworkPolicy::Denied` the safe default it is meant to be — a spec that
/// names ports and then denies the network gets the denial, which is the
/// stricter of the two.
fn port_flags(spec: &BoxSpec) -> Vec<String> {
    if !spec.network.allows_egress() {
        return Vec::new();
    }

    let mut flags = Vec::new();
    for port in &spec.ports {
        flags.push("--publish".to_owned());
        flags.push(match port.host {
            // Docker picks a free host port when only the guest side is named.
            None => port.guest.to_string(),
            Some(host) => format!("{host}:{}", port.guest),
        });
    }
    flags
}

/// The `docker exec` command that runs `request` inside a box.
///
/// # Errors
///
/// Returns [`Error::EmptyCommand`] when the request names no program.
pub(super) fn exec(namespace: &str, id: &BoxId, request: &ExecRequest) -> Result<Vec<String>> {
    if request.argv.is_empty() {
        return Err(Error::EmptyCommand {
            sandbox: NAME.to_owned(),
        });
    }

    let mut argv = vec!["docker".to_owned(), "exec".to_owned()];
    if let Some(cwd) = &request.cwd {
        argv.push("--workdir".to_owned());
        argv.push(cwd.display().to_string());
    }
    for (key, value) in &request.env {
        argv.push("--env".to_owned());
        argv.push(format!("{key}={value}"));
    }
    argv.push(container_name(namespace, id));
    // `--` is not accepted here, so the container name is the last flag-like
    // argument and everything after it belongs to the command.
    argv.extend(request.argv.iter().cloned());
    Ok(argv)
}

/// The `docker inspect` command that reports one container's state.
pub(super) fn inspect(namespace: &str, id: &BoxId) -> Vec<String> {
    vec![
        "docker".to_owned(),
        "inspect".to_owned(),
        "--format".to_owned(),
        "{{.State.Status}}".to_owned(),
        container_name(namespace, id),
    ]
}

/// The `docker commit` command that captures a box's filesystem.
pub(super) fn commit(namespace: &str, id: &BoxId) -> Vec<String> {
    vec![
        "docker".to_owned(),
        "commit".to_owned(),
        container_name(namespace, id),
    ]
}

/// The `docker rm` command that destroys a box.
///
/// Forced, because a box is destroyed while still running by design.
pub(super) fn remove(namespace: &str, id: &BoxId) -> Vec<String> {
    vec![
        "docker".to_owned(),
        "rm".to_owned(),
        "--force".to_owned(),
        "--volumes".to_owned(),
        container_name(namespace, id),
    ]
}

/// Turn `docker commit` output into a snapshot identifier.
///
/// Docker prints `sha256:<64 hex>`, which is not a valid tinybox identifier —
/// `:` is outside the permitted set. Keeping a short prefix of the digest gives
/// a valid identifier that Docker still accepts as an image reference, so no
/// separate snapshot registry is needed.
///
/// # Errors
///
/// Returns [`Error::Backend`] when the output is not a digest, which would mean
/// Docker changed its output format.
pub(super) fn snapshot_of_commit(output: &str) -> Result<SnapshotId> {
    let digest = output
        .trim()
        .rsplit(':')
        .next()
        .unwrap_or_default()
        .trim()
        .to_owned();

    let short = digest
        .get(..SNAPSHOT_DIGEST_LENGTH)
        .filter(|short| short.chars().all(|c| c.is_ascii_hexdigit()))
        .ok_or_else(|| Error::Backend {
            sandbox: NAME.to_owned(),
            operation: "read the committed image digest",
            message: format!("expected sha256:<digest>, got {:?}", output.trim()),
        })?;

    SnapshotId::new(format!("{SNAPSHOT_PREFIX}{short}"))
}

/// The image reference a snapshot identifier points at.
///
/// The inverse of [`snapshot_of_commit`]: strip the prefix and hand Docker the
/// short digest, which it resolves the same way it resolves any short id.
pub(super) fn image_of_snapshot(snapshot: &SnapshotId) -> String {
    snapshot
        .as_str()
        .strip_prefix(SNAPSHOT_PREFIX)
        .unwrap_or_else(|| snapshot.as_str())
        .to_owned()
}
