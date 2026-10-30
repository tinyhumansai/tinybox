//! The `openshell sandbox` commands this backend issues, as pure functions.
//!
//! Nothing here runs a process. Every decision about how a box becomes an
//! `OpenShell` sandbox — its name, labels, limits, and which specs are refused —
//! is a value returned from this module, so it can be asserted without a
//! gateway.

use tinybox_core::{
    BoxId, BoxSpec, BoxState, Capability, Constraint, Enforcement, Error, ExecRequest,
    NetworkPolicy, Resources, Result, WorkspaceSource,
};

use super::NAME;

/// The label naming the tinybox box a sandbox belongs to.
pub const BOX_LABEL: &str = "tinybox-box";

/// The label naming the tinybox namespace a sandbox belongs to.
///
/// Listing by this label finds every sandbox one store created, which is how a
/// restarted host can tell its own sandboxes from anyone else's.
pub const NAMESPACE_LABEL: &str = "tinybox-namespace";

/// The longest sandbox name this backend produces.
///
/// `OpenShell`'s Kubernetes driver names pods and services after the sandbox,
/// and a Kubernetes name is a DNS label: at most 63 characters.
const MAX_NAME_LENGTH: usize = 63;

/// The longest namespace this backend accepts.
///
/// What is left of a sandbox name once the `tinybox-` prefix and the shortest
/// box suffix (`-box-0`) are taken out, so a valid namespace always leaves room
/// for a box. Long enough for a UUID-based namespace, such as the resource
/// identifiers the tinybox module uses. [`checked_name`] still refuses a name
/// that a long box identifier pushes past the limit.
const MAX_NAMESPACE_LENGTH: usize = MAX_NAME_LENGTH - "tinybox-".len() - "-box-0".len();

/// The `OpenShell` sandbox name for a box.
///
/// Box identifiers are unique within a store; `OpenShell` names are unique
/// within a gateway workspace. The namespace bridges those scopes, as it does
/// for Docker container names, and the `tinybox-` prefix says where the
/// sandbox came from.
#[must_use]
pub fn sandbox_name(namespace: &str, id: &BoxId) -> String {
    format!("tinybox-{namespace}-{id}")
}

/// Whether `value` is a usable namespace.
///
/// A namespace ends up inside a DNS label, so it is held to that alphabet:
/// lowercase ASCII letters, digits and `-`, not starting or ending with `-`.
pub(super) fn is_valid_namespace(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_NAMESPACE_LENGTH
        && !value.starts_with('-')
        && !value.ends_with('-')
        && value.chars().all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
        })
}

/// Check that a box's sandbox name is a DNS label.
///
/// # Errors
///
/// Returns [`Error::InvalidIdentifier`] when the box identifier carries a
/// character a DNS label refuses (uppercase, `_` or `.`) or the name is too
/// long. A store that allocates `box-<n>` never trips this.
fn checked_name(namespace: &str, id: &BoxId) -> Result<String> {
    let name = sandbox_name(namespace, id);
    let valid = name.len() <= MAX_NAME_LENGTH
        && !name.ends_with('-')
        && name.chars().all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
        });
    if valid {
        Ok(name)
    } else {
        Err(Error::InvalidIdentifier {
            kind: "openshell sandbox name",
            value: name,
        })
    }
}

/// Refuse what `OpenShell` cannot honor for this spec, before anything runs.
///
/// # Errors
///
/// - [`Error::UnsupportedWorkspaceSource`] for anything but an OCI image.
/// - [`Error::ConstraintNotEnforced`] for a network policy other than
///   [`NetworkPolicy::Denied`].
/// - [`Error::Unsupported`] when the spec publishes ports.
fn check_spec(spec: &BoxSpec) -> Result<String> {
    let image = match &spec.source {
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
    Ok(image)
}

fn unsupported_source(kind: &'static str) -> Error {
    Error::UnsupportedWorkspaceSource {
        sandbox: NAME.to_owned(),
        kind,
    }
}

/// The `openshell sandbox create` command that creates a box and waits for it.
///
/// With `-o json` the CLI returns only once the sandbox is `Ready` (or fails),
/// and `--detach` keeps it from attaching a shell. Environment values travel
/// as `--env-from KEY`, which reads them from the CLI's own environment, so
/// they never appear on its argv; the caller puts them there.
///
/// # Errors
///
/// Everything [`check_spec`] and [`resource_flags`] refuse, and [`Error::InvalidIdentifier`] when
/// the box's name is not a DNS label.
pub(super) fn create(namespace: &str, id: &BoxId, spec: &BoxSpec) -> Result<Vec<String>> {
    let image = check_spec(spec)?;
    let mut argv = openshell(["sandbox", "create", "--name"]);
    argv.push(checked_name(namespace, id)?);
    argv.extend(["--from".to_owned(), image]);
    argv.extend(resource_flags(&spec.resources)?);
    argv.extend([
        "--label".to_owned(),
        format!("{BOX_LABEL}={id}"),
        "--label".to_owned(),
        format!("{NAMESPACE_LABEL}={namespace}"),
    ]);
    for key in spec.env.keys() {
        argv.push("--env-from".to_owned());
        argv.push(key.clone());
    }
    // A host has no person at the prompt, so a missing provider must fail the
    // create rather than wait for an answer.
    argv.extend(["--no-auto-providers", "--no-tty", "--detach", "-o", "json"].map(str::to_owned));
    Ok(argv)
}

/// Translate tinybox resources into `OpenShell`'s limit flags.
///
/// `OpenShell` takes Kubernetes quantities. CPU is exact in millicores. Memory
/// is a whole number of mebibytes: a byte count that is not one is refused
/// rather than rounded, because rounding up would exceed the maximum the
/// caller asked for and rounding down would give less than it needs. There is
/// no per-sandbox process or disk limit, which is why `pids_max` and
/// `disk_bytes` are not applied and the backend declares neither
/// `Capability::ResourceLimits` nor the `Pids` and `Disk` constraints.
///
/// # Errors
///
/// Returns [`Error::ConstraintNotEnforced`] for a memory limit that is not a
/// whole number of mebibytes.
fn resource_flags(resources: &Resources) -> Result<Vec<String>> {
    const MEBIBYTE: u64 = 1024 * 1024;
    if !resources.memory_bytes.is_multiple_of(MEBIBYTE) {
        return Err(Error::ConstraintNotEnforced {
            sandbox: NAME.to_owned(),
            constraint: Constraint::Memory,
            enforcement: Enforcement::Unsupported,
        });
    }
    Ok(vec![
        "--cpu".to_owned(),
        format!("{}m", resources.cpu_millis),
        "--memory".to_owned(),
        format!("{}Mi", resources.memory_bytes / MEBIBYTE),
    ])
}

/// The `openshell sandbox exec` command that runs `request` inside a box.
///
/// `--no-tty` and `--no-login-shell` keep the run predictable for automation:
/// no terminal emulation in the output, and no profile scripts in the sandbox
/// that could run before the command. Unlike create, exec has no way to read
/// values from the CLI's environment, so environment values do appear on the
/// CLI's argv; `OpenShell`'s own guidance is to pass secrets as providers, never
/// as environment.
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
    let mut argv = openshell(["sandbox", "exec", "--name"]);
    argv.push(sandbox_name(namespace, id));
    argv.extend(["--no-tty", "--no-login-shell"].map(str::to_owned));
    if let Some(cwd) = &request.cwd {
        argv.push("--workdir".to_owned());
        argv.push(cwd.display().to_string());
    }
    for (key, value) in &request.env {
        argv.push("--env".to_owned());
        argv.push(format!("{key}={value}"));
    }
    argv.push("--".to_owned());
    argv.extend(request.argv.iter().cloned());
    Ok(argv)
}

/// The `openshell sandbox get` command that reports one sandbox as JSON.
pub(super) fn get(namespace: &str, id: &BoxId) -> Vec<String> {
    let mut argv = openshell(["sandbox", "get"]);
    argv.push(sandbox_name(namespace, id));
    argv.extend(["-o", "json"].map(str::to_owned));
    argv
}

/// The `openshell sandbox delete` command that removes one sandbox.
pub(super) fn delete(namespace: &str, id: &BoxId) -> Vec<String> {
    let mut argv = openshell(["sandbox", "delete"]);
    argv.push(sandbox_name(namespace, id));
    argv
}

/// Whether a failed `openshell` call failed because the sandbox is gone.
///
/// The gateway answers an unknown name with a gRPC `NotFound`, which the CLI
/// prints as "not found" in its diagnostic. That text is the only signal the
/// CLI offers, so it is matched case-insensitively and nowhere else.
pub(super) fn is_missing(stderr: &str) -> bool {
    stderr.to_ascii_lowercase().contains("not found")
}

/// Whether a failed `sandbox create` failed because the name is taken.
///
/// Then the sandbox is someone else's, so a failed create must not delete it.
pub(super) fn is_already_exists(stderr: &str) -> bool {
    stderr.to_ascii_lowercase().contains("already exists")
}

/// The box state a `sandbox get -o json` answer describes.
///
/// # Errors
///
/// Returns [`Error::Backend`] when the output is not JSON or has no string
/// phase (`provisioning.phase`, or a top-level `phase`), rather than guessing a state from a shape this code does not know.
pub(super) fn state_of(json: &str) -> Result<BoxState> {
    let phase = serde_json::from_str::<serde_json::Value>(json)
        .ok()
        .and_then(|value| {
            value
                .pointer("/provisioning/phase")
                .or_else(|| value.get("phase"))?
                .as_str()
                .map(str::to_owned)
        })
        .ok_or_else(|| Error::Backend {
            sandbox: NAME.to_owned(),
            operation: "read the sandbox phase",
            message: format!("unexpected output: {json}"),
        })?;
    Ok(match phase.as_str() {
        "Provisioning" | "Starting" => BoxState::Creating,
        "Ready" => BoxState::Ready,
        "Stopping" | "Stopped" => BoxState::Stopped,
        "Suspending" | "Suspended" => BoxState::Paused,
        "Completed" | "Deleting" => BoxState::Archived,
        // `Error`, `Unknown`, `Unspecified`, and any phase added after this
        // was written: none of them may be sent commands.
        _ => BoxState::Failed,
    })
}

fn openshell<const N: usize>(parts: [&str; N]) -> Vec<String> {
    std::iter::once("openshell")
        .chain(parts)
        .map(str::to_owned)
        .collect()
}

#[cfg(test)]
#[path = "args_tests.rs"]
mod tests;
