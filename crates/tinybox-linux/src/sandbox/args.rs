//! Building the `bwrap` command line, and the cgroup wrapper around it.
//!
//! Pure functions, as with the Docker backend: what a sandbox binds, unshares,
//! and limits *is* the security boundary, so every one of those decisions
//! should be a value a test can assert on rather than something that only
//! happens at runtime.

use std::path::Path;

use tinybox_core::{BoxSpec, Error, ExecRequest, Resources, Result, WorkspaceSource};

use super::NAME;

/// Where a box's directory appears inside the sandbox.
pub const WORKSPACE_MOUNT: &str = "/workspace";

/// The read-only tree the sandbox gets a userland from.
///
/// Only `/usr` is bound, with the usual merged-`/usr` symlinks on top. Binding
/// the host's `/` read-only would be simpler and would expose every file the
/// user can read; this exposes the system's programs and libraries and nothing
/// else.
const USR: &str = "/usr";

/// Files a normal command expects to exist.
///
/// Deliberately a short list rather than `--ro-bind /etc /etc`. Name resolution
/// and TLS need these three; binding the whole of `/etc` would hand the box
/// every credential, host key, and configuration file the user can read.
/// A box that needs more should be given it explicitly.
const ETC_FILES: [&str; 4] = [
    "/etc/passwd",
    "/etc/group",
    "/etc/resolv.conf",
    "/etc/ssl/certs",
];

/// The workspace directory a spec names.
///
/// # Errors
///
/// Returns [`Error::UnsupportedWorkspaceSource`] for every source except
/// [`WorkspaceSource::LocalDir`]. There is no image machinery here: this
/// backend binds a directory the caller already has.
pub(super) fn workspace_dir(spec: &BoxSpec) -> Result<&Path> {
    match &spec.source {
        WorkspaceSource::LocalDir(path) => Ok(path),
        WorkspaceSource::OciImage(_) => Err(unsupported("OCI image")),
        WorkspaceSource::Snapshot(_) => Err(unsupported("snapshot")),
        WorkspaceSource::GitRepo { .. } => Err(unsupported("git repository")),
        // Non-exhaustive: a source added to core later lands here. Refusing is
        // the only honest answer, since guessing would produce a sandbox
        // holding something other than what was asked for.
        _ => Err(unsupported(
            "workspace source this backend does not recognize",
        )),
    }
}

/// A refusal naming the kind of source that was rejected.
fn unsupported(kind: &'static str) -> Error {
    Error::UnsupportedWorkspaceSource {
        sandbox: NAME.to_owned(),
        kind,
    }
}

/// The full command that runs `request` inside a sandbox over `spec`.
///
/// # Errors
///
/// Returns [`Error::EmptyCommand`] when the request names no program, and
/// [`Error::UnsupportedWorkspaceSource`] when the spec names a source this
/// backend cannot bind.
pub(super) fn exec(spec: &BoxSpec, request: &ExecRequest, limits: bool) -> Result<Vec<String>> {
    if request.argv.is_empty() {
        return Err(Error::EmptyCommand {
            sandbox: NAME.to_owned(),
        });
    }

    let mut argv = if limits {
        cgroup_prefix(&spec.resources)
    } else {
        Vec::new()
    };
    argv.extend(bwrap(spec, request)?);
    Ok(argv)
}

/// Wrap the sandbox in a transient systemd scope so cgroup limits apply.
///
/// Rootless cgroup v2 limits go through the user's own systemd session, which
/// is the only way an unprivileged process can get a delegated cgroup. That is
/// also why limits are opt-in: a machine with no systemd user session cannot
/// provide them, and a sandbox that accepted a memory cap it could not apply
/// would be claiming something untrue.
fn cgroup_prefix(resources: &Resources) -> Vec<String> {
    vec![
        "systemd-run".to_owned(),
        "--user".to_owned(),
        "--scope".to_owned(),
        // Without this, systemd narrates every scope it creates onto stderr and
        // the noise ends up interleaved with the command's own output.
        "--quiet".to_owned(),
        "--property".to_owned(),
        format!("MemoryMax={}", resources.memory_bytes),
        // Without this the cap is advisory on any machine with swap: the kernel
        // pushes the overage out rather than killing the process, and a box
        // asked for 64 MiB happily uses 200. Docker caps swap alongside memory
        // for the same reason. Zero, not the memory figure, because a sandbox
        // that starts swapping has already lost the performance the limit was
        // protecting.
        "--property".to_owned(),
        "MemorySwapMax=0".to_owned(),
        "--property".to_owned(),
        // systemd takes CPU as a percentage where 100% is one core, and
        // thousandths convert by a factor of ten.
        format!("CPUQuota={}%", resources.cpu_millis / 10),
        "--property".to_owned(),
        format!("TasksMax={}", resources.pids_max),
        "--".to_owned(),
    ]
}

/// The `bwrap` invocation itself.
fn bwrap(spec: &BoxSpec, request: &ExecRequest) -> Result<Vec<String>> {
    let workspace = workspace_dir(spec)?;
    let mut argv = vec!["bwrap".to_owned()];

    // The namespaces that make this a sandbox rather than a chroot.
    for flag in [
        "--unshare-user",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--unshare-cgroup",
    ] {
        argv.push(flag.to_owned());
    }
    if !spec.network.allows_egress() {
        // A network namespace with nothing in it: loopback and no route out.
        argv.push("--unshare-net".to_owned());
    }

    // If tinybox dies, the sandbox dies with it rather than being reparented to
    // init and outliving the box it belongs to.
    argv.push("--die-with-parent".to_owned());
    // A new session, so the sandboxed process cannot inject keystrokes into the
    // caller's terminal through TIOCSTI.
    argv.push("--new-session".to_owned());

    argv.extend(root_filesystem());

    argv.push("--bind".to_owned());
    argv.push(workspace.display().to_string());
    argv.push(WORKSPACE_MOUNT.to_owned());
    argv.push("--chdir".to_owned());
    argv.push(request.cwd.as_ref().map_or_else(
        || WORKSPACE_MOUNT.to_owned(),
        |cwd| cwd.display().to_string(),
    ));

    // The box's own environment first, then the request's on top, matching
    // every other backend.
    argv.push("--clearenv".to_owned());
    for (key, value) in spec.env.iter().chain(&request.env) {
        argv.push("--setenv".to_owned());
        argv.push(key.clone());
        argv.push(value.clone());
    }

    argv.push("--".to_owned());
    argv.extend(request.argv.iter().cloned());
    Ok(argv)
}

/// The read-only root the sandbox sees.
fn root_filesystem() -> Vec<String> {
    let mut argv = vec![
        "--ro-bind".to_owned(),
        USR.to_owned(),
        USR.to_owned(),
        // Merged-`/usr` layouts reach the same files through these, and a
        // program's interpreter path is usually one of them.
        "--symlink".to_owned(),
        "usr/bin".to_owned(),
        "/bin".to_owned(),
        "--symlink".to_owned(),
        "usr/sbin".to_owned(),
        "/sbin".to_owned(),
        "--symlink".to_owned(),
        "usr/lib".to_owned(),
        "/lib".to_owned(),
        "--symlink".to_owned(),
        "usr/lib64".to_owned(),
        "/lib64".to_owned(),
        // A private process table, device nodes, and scratch space. `--proc`
        // mounts a fresh procfs for the box's own namespace, which is what
        // makes host processes invisible rather than merely unreadable.
        "--proc".to_owned(),
        "/proc".to_owned(),
        "--dev".to_owned(),
        "/dev".to_owned(),
        "--tmpfs".to_owned(),
        "/tmp".to_owned(),
    ];

    for file in ETC_FILES {
        // Missing files are skipped rather than fatal: a machine without
        // `/etc/resolv.conf` is unusual but not broken, and refusing to start
        // over it would be worse than starting without name resolution.
        argv.push("--ro-bind-try".to_owned());
        argv.push(file.to_owned());
        argv.push(file.to_owned());
    }
    argv
}
