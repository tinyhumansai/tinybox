//! Safety policy for one-shot Docker runs.
//!
//! The checks inspect the request's network mode and mount paths without
//! touching the daemon. Mount paths are also resolved on the host filesystem,
//! because Docker mounts what a path resolves to, so a host can rely on the
//! module refusing a dangerous run before any container exists.

use std::path::{Component, Path, PathBuf};

/// Host paths that must never be bind-mounted into a one-shot container, nor
/// any directory that contains one of them.
pub const DANGEROUS_MOUNTS: &[&str] = &[
    "/",
    "/etc",
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/proc",
    "/sys",
    "/run",
    "/var/lib/docker",
];

/// Host trees whose every path is refused: kernel interfaces, runtime sockets
/// (including rootless `/run/user/<uid>/docker.sock`) and Docker's own state.
const DANGEROUS_TREES: &[&str] = &["/proc", "/sys", "/run", "/var/lib/docker"];

/// The network mode that shares the host's network stack.
pub const HOST_NETWORK: &str = "host";

/// Describe every way a one-shot run would weaken container isolation.
///
/// `workspace` is `None` for runs that mount no workspace. An empty result
/// means the run may proceed.
#[must_use]
pub fn run_policy_issues(
    network: Option<&str>,
    workspace: Option<&str>,
    read_only_mounts: &[String],
) -> Vec<String> {
    let mut issues = Vec::new();
    if network == Some(HOST_NETWORK) {
        issues.push("Docker run uses the host network, which defeats network isolation".into());
    }
    for mount in read_only_mounts {
        if is_dangerous_mount(mount) {
            issues.push(format!("Dangerous read-only mount: {mount}"));
        }
    }
    if let Some(workspace) = workspace
        && is_dangerous_mount(workspace)
    {
        issues.push(format!("Workspace is a dangerous path: {workspace}"));
    }
    issues
}

/// Whether bind-mounting `path` would expose a dangerous host path.
///
/// Docker treats a relative source as a named volume and, on Unix, `:`/`,`
/// as option separators, so those are refused outright. Otherwise the lexical and the
/// canonical form of `path` are each compared with the literal and canonical
/// form of every [`DANGEROUS_MOUNTS`] entry: a path is dangerous when it is one
/// of them or contains one, when it lies inside a [`DANGEROUS_TREES`] root, or
/// when it resolves to a socket.
///
/// ponytail: the policy and the argv builder canonicalize separately, so a
/// symlink swapped in between is not seen (TOCTOU); mount the path this check
/// resolved if that matters.
#[must_use]
pub(crate) fn is_dangerous_mount(path: &str) -> bool {
    // `has_root`, not `is_absolute`: on Windows `/etc` names the same tree as
    // on Unix, and a drive path legitimately carries a `:`.
    if !Path::new(path).has_root() || (cfg!(unix) && path.contains([':', ','])) {
        return true;
    }
    let canonical = Path::new(path).canonicalize().ok();
    if canonical.as_deref().is_some_and(is_socket) {
        return true;
    }
    let forms: Vec<PathBuf> = std::iter::once(lexical(Path::new(path)))
        .chain(canonical)
        .collect();
    let with_canonical = |raw: &&str| {
        let raw = Path::new(raw);
        std::iter::once(raw.to_path_buf()).chain(raw.canonicalize().ok())
    };
    let contains_dangerous = DANGEROUS_MOUNTS
        .iter()
        .flat_map(with_canonical)
        .any(|dangerous| forms.iter().any(|form| dangerous.starts_with(form)));
    let inside_tree = DANGEROUS_TREES
        .iter()
        .flat_map(with_canonical)
        .any(|tree| forms.iter().any(|form| form.starts_with(&tree)));
    contains_dangerous || inside_tree
}

/// `path` with `.` and `..` folded away without touching the filesystem.
fn lexical(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other),
        }
    }
    out
}

#[cfg(unix)]
fn is_socket(path: &Path) -> bool {
    use std::os::unix::fs::FileTypeExt as _;
    path.metadata()
        .is_ok_and(|meta| meta.file_type().is_socket())
}

#[cfg(not(unix))]
fn is_socket(_path: &Path) -> bool {
    false
}

#[cfg(test)]
#[path = "policy_tests.rs"]
mod tests;
