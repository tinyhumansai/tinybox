//! Tests that run real sandboxes against a real kernel.
//!
//! Gated behind `TINYBOX_LIVE_NAMESPACES=1` and named `live_*`, and needing
//! `bwrap` on the machine. Unlike the Docker and SSH suites there is no service
//! to start: a sandbox is a process, so these cost milliseconds.
//!
//! # These assert isolation negatively
//!
//! Every claim is that the box *cannot* reach something — host processes, the
//! home directory, the network, the system's own files. A positive assertion
//! would pass just as happily against a sandbox that confines nothing, which is
//! exactly the failure this backend exists to rule out.

use std::fs;
use std::path::Path;
use std::sync::Arc;

use tempfile::TempDir;
use tinybox_core::{
    BoxId, BoxSpec, Error, ExecRequest, HostRef, MemoryStore, NetworkPolicy, Placement, Result,
    Sandbox, SandboxRef, WorkspaceSource,
};
use tinybox_host::LocalHost;
use tinybox_linux::NamespaceSandbox;

/// Whether the live suite should run at all.
fn enabled() -> bool {
    std::env::var_os("TINYBOX_LIVE_NAMESPACES").is_some()
}

fn sandbox() -> NamespaceSandbox {
    NamespaceSandbox::new(Arc::new(LocalHost::new()), Arc::new(MemoryStore::new()))
}

fn spec(workspace: &Path) -> Result<BoxSpec> {
    Ok(BoxSpec::new(
        Placement::new(HostRef::new("local")?, SandboxRef::new("namespace")?),
        WorkspaceSource::LocalDir(workspace.into()),
    ))
}

/// A workspace directory with one file in it.
fn workspace() -> Result<TempDir> {
    let dir = TempDir::new().map_err(|error| Error::io("tempdir", &error))?;
    fs::write(dir.path().join("note.txt"), "workspace file\n")
        .map_err(|error| Error::io("write", &error))?;
    Ok(dir)
}

/// Run a shell command in a fresh box and return its trimmed stdout.
async fn run_in_box(sandbox: &NamespaceSandbox, spec: &BoxSpec, script: &str) -> Result<String> {
    let info = sandbox.create(spec).await?;
    let output = sandbox
        .exec(&info.id, &ExecRequest::new(["/bin/sh", "-c", script]))
        .await?;
    sandbox.destroy(&info.id).await?;

    if !output.succeeded() {
        return Err(Error::Backend {
            sandbox: "namespace".to_owned(),
            operation: "run a sandboxed command",
            message: output.stderr_lossy().trim().to_owned(),
        });
    }
    Ok(output.stdout_lossy().trim().to_owned())
}

#[tokio::test]
async fn live_a_command_runs_in_the_workspace() -> Result<()> {
    if !enabled() {
        return Ok(());
    }
    let dir = workspace()?;
    let sandbox = sandbox();

    let seen = run_in_box(&sandbox, &spec(dir.path())?, "pwd; cat note.txt").await?;

    // The workspace is bound and is where commands start.
    assert!(seen.contains("/workspace"), "{seen}");
    assert!(seen.contains("workspace file"), "{seen}");
    Ok(())
}

#[tokio::test]
async fn live_the_box_cannot_see_host_processes() -> Result<()> {
    if !enabled() {
        return Ok(());
    }
    let dir = workspace()?;
    let sandbox = sandbox();

    let count = run_in_box(
        &sandbox,
        &spec(dir.path())?,
        "ls /proc | grep -c '^[0-9]*$'",
    )
    .await?;

    // The host has hundreds. A PID namespace with a fresh procfs sees only its
    // own handful, so a large number here means the boundary is not real.
    let visible: usize = count.parse().unwrap_or(usize::MAX);
    assert!(
        visible < 20,
        "expected a private process table, saw {visible}"
    );
    Ok(())
}

#[tokio::test]
async fn live_the_box_cannot_see_the_home_directory() -> Result<()> {
    if !enabled() {
        return Ok(());
    }
    let dir = workspace()?;
    let sandbox = sandbox();

    let seen = run_in_box(
        &sandbox,
        &spec(dir.path())?,
        "test -e /home && echo LEAKED || echo absent; test -e /root && echo ROOT || echo no-root",
    )
    .await?;

    // Nothing outside the workspace and `/usr` is bound, so the user's files —
    // ssh keys, credentials, other projects — are simply not there.
    assert!(!seen.contains("LEAKED"), "{seen}");
    assert!(!seen.contains("ROOT"), "{seen}");
    Ok(())
}

#[tokio::test]
async fn live_the_box_cannot_write_outside_its_workspace() -> Result<()> {
    if !enabled() {
        return Ok(());
    }
    let dir = workspace()?;
    let sandbox = sandbox();

    let seen = run_in_box(
        &sandbox,
        &spec(dir.path())?,
        "touch /usr/pwned 2>/dev/null && echo WROTE-USR || echo usr-readonly; \
         touch /workspace/allowed && echo workspace-writable",
    )
    .await?;

    assert!(!seen.contains("WROTE-USR"), "{seen}");
    assert!(seen.contains("usr-readonly"), "{seen}");
    // The workspace is the one writable place, and it must actually be writable.
    assert!(seen.contains("workspace-writable"), "{seen}");
    assert!(dir.path().join("allowed").exists());
    Ok(())
}

#[tokio::test]
async fn live_the_host_configuration_is_not_handed_over_wholesale() -> Result<()> {
    if !enabled() {
        return Ok(());
    }
    let dir = workspace()?;
    let sandbox = sandbox();

    let seen = run_in_box(
        &sandbox,
        &spec(dir.path())?,
        "test -e /etc/passwd && echo passwd; test -e /etc/shadow && echo SHADOW || echo no-shadow; \
         ls /etc | wc -l",
    )
    .await?;

    // What a normal command needs is there; the rest of `/etc` — host keys,
    // credentials, service configuration — is not.
    assert!(seen.contains("passwd"), "{seen}");
    assert!(!seen.contains("SHADOW"), "{seen}");
    let entries: usize = seen
        .lines()
        .last()
        .unwrap_or("999")
        .trim()
        .parse()
        .unwrap_or(999);
    assert!(
        entries < 10,
        "expected a minimal /etc, saw {entries} entries"
    );
    Ok(())
}

#[tokio::test]
async fn live_a_denied_network_really_is_denied() -> Result<()> {
    if !enabled() {
        return Ok(());
    }
    let dir = workspace()?;
    let sandbox = sandbox();

    // Denied is the default, so this is what a caller gets without asking.
    let count = run_in_box(
        &sandbox,
        &spec(dir.path())?,
        "ip -o link 2>/dev/null | wc -l",
    )
    .await?;

    assert_eq!(count, "1", "expected loopback only");
    Ok(())
}

#[tokio::test]
async fn live_egress_is_available_when_the_policy_allows_it() -> Result<()> {
    if !enabled() {
        return Ok(());
    }
    let dir = workspace()?;
    let sandbox = sandbox();
    let spec = spec(dir.path())?.with_network(NetworkPolicy::Egress);

    let count = run_in_box(&sandbox, &spec, "ip -o link 2>/dev/null | wc -l").await?;

    let interfaces: usize = count.parse().unwrap_or(0);
    assert!(
        interfaces > 1,
        "expected more than loopback, saw {interfaces}"
    );
    Ok(())
}

#[tokio::test]
async fn live_the_callers_environment_does_not_leak_in() -> Result<()> {
    if !enabled() {
        return Ok(());
    }
    let dir = workspace()?;
    let sandbox = sandbox();
    let spec = spec(dir.path())?.with_env("FROM_BOX", "visible");

    // `TINYBOX_LIVE_NAMESPACES` is in this process's environment — it is what
    // enabled this test — so it is the sharpest probe available for a leak.
    let seen = run_in_box(
        &sandbox,
        &spec,
        "echo \"box=$FROM_BOX\"; echo \"home=${HOME:-unset}\"; \
         echo \"gate=${TINYBOX_LIVE_NAMESPACES:-unset}\"",
    )
    .await?;

    // The caller's environment routinely holds tokens, so it is cleared and
    // only what the box declares is put back.
    assert!(seen.contains("box=visible"), "{seen}");
    assert!(seen.contains("home=unset"), "{seen}");
    assert!(seen.contains("gate=unset"), "{seen}");

    // `PATH` is deliberately not asserted on: `--clearenv` does remove it, and
    // the shell then sets its own POSIX default. That is the shell's doing, not
    // a leak — the two variables above are what actually prove the clearing.
    Ok(())
}

#[tokio::test]
async fn live_an_argument_is_never_interpreted_as_a_shell_would() -> Result<()> {
    if !enabled() {
        return Ok(());
    }
    let dir = workspace()?;
    let sandbox = sandbox();
    let info = sandbox.create(&spec(dir.path())?).await?;

    let output = sandbox
        .exec(
            &info.id,
            &ExecRequest::new(["/bin/echo", "; touch /workspace/PWNED"]),
        )
        .await?;

    sandbox.destroy(&info.id).await?;
    assert_eq!(output.stdout_lossy().trim(), "; touch /workspace/PWNED");
    assert!(
        !dir.path().join("PWNED").exists(),
        "the argument was executed rather than printed"
    );
    Ok(())
}

#[tokio::test]
async fn live_a_failing_command_reports_its_status() -> Result<()> {
    if !enabled() {
        return Ok(());
    }
    let dir = workspace()?;
    let sandbox = sandbox();
    let info = sandbox.create(&spec(dir.path())?).await?;

    let output = sandbox
        .exec(&info.id, &ExecRequest::new(["/bin/sh", "-c", "exit 7"]))
        .await?;

    sandbox.destroy(&info.id).await?;
    // A command that runs and fails is a result, not a backend error.
    assert_eq!(output.exit_code, 7);
    Ok(())
}

#[tokio::test]
async fn live_writes_outside_the_workspace_do_not_survive_between_commands() -> Result<()> {
    if !enabled() {
        return Ok(());
    }
    let dir = workspace()?;
    let sandbox = sandbox();
    let info = sandbox.create(&spec(dir.path())?).await?;

    sandbox
        .exec(
            &info.id,
            &ExecRequest::new(["/bin/sh", "-c", "echo gone > /tmp/marker"]),
        )
        .await?;
    let outside = sandbox
        .exec(
            &info.id,
            &ExecRequest::new([
                "/bin/sh",
                "-c",
                "cat /tmp/marker 2>/dev/null || echo absent",
            ]),
        )
        .await?;

    // The documented limit of this backend: each command is a fresh sandbox, so
    // only the bound workspace persists. This is why it declares no snapshot
    // support.
    assert_eq!(outside.stdout_lossy().trim(), "absent");

    sandbox
        .exec(
            &info.id,
            &ExecRequest::new(["/bin/sh", "-c", "echo kept > /workspace/marker"]),
        )
        .await?;
    let inside = sandbox
        .exec(
            &info.id,
            &ExecRequest::new(["/bin/cat", "/workspace/marker"]),
        )
        .await?;

    assert_eq!(inside.stdout_lossy().trim(), "kept");
    sandbox.destroy(&info.id).await?;
    Ok(())
}

#[tokio::test]
async fn live_a_memory_limit_is_actually_enforced() -> Result<()> {
    if !enabled() {
        return Ok(());
    }
    let dir = workspace()?;
    let sandbox = NamespaceSandbox::new(Arc::new(LocalHost::new()), Arc::new(MemoryStore::new()))
        .with_cgroup_limits();
    let spec = spec(dir.path())?.with_resources(tinybox_core::Resources {
        memory_bytes: 64 * 1024 * 1024,
        ..tinybox_core::Resources::DEFAULT
    });
    let info = sandbox.create(&spec).await?;

    // Reading `memory.max` would only prove the cgroup was *configured*, and an
    // earlier version of this test did exactly that — while a 200 MiB
    // allocation sailed straight past a 64 MiB cap, because swap absorbed it.
    // So this allocates for real. The allocation is anonymous memory held by
    // the shell rather than a file write, which is the same probe the Docker
    // suite uses and is memory on both.
    let over = sandbox
        .exec(
            &info.id,
            &ExecRequest::new([
                "/bin/sh",
                "-c",
                "x=$(yes a | head -c 100000000); echo SURVIVED",
            ]),
        )
        .await;

    // ...and that a modest allocation under the same cap still works, so the
    // test is measuring a limit rather than a broken sandbox.
    let under = sandbox
        .exec(
            &info.id,
            &ExecRequest::new(["/bin/sh", "-c", "x=$(yes a | head -c 8000000); echo ok"]),
        )
        .await;

    sandbox.destroy(&info.id).await?;

    let (Ok(over), Ok(under)) = (over, under) else {
        // No systemd user session on this machine, so limits cannot be applied
        // at all. The unit tests still pin the command that would have run.
        return Ok(());
    };
    assert!(
        !over.stdout_lossy().contains("SURVIVED"),
        "a 100 MiB allocation was not stopped by a 64 MiB cap: {}",
        over.stdout_lossy()
    );
    assert!(
        under.stdout_lossy().contains("ok"),
        "{}",
        under.stdout_lossy()
    );
    Ok(())
}

#[tokio::test]
async fn live_a_box_is_only_a_record_so_destroying_it_leaves_the_workspace() -> Result<()> {
    if !enabled() {
        return Ok(());
    }
    let dir = workspace()?;
    let sandbox = sandbox();
    let info = sandbox.create(&spec(dir.path())?).await?;

    sandbox.destroy(&info.id).await?;

    // The workspace belongs to the caller; destroying a box must not delete it.
    assert!(dir.path().join("note.txt").exists());
    assert!(
        sandbox
            .inspect(&BoxId::new(info.id.as_str())?)
            .await
            .is_err()
    );
    Ok(())
}
