//! Tests that drive a real Docker daemon.
//!
//! Gated behind `TINYBOX_LIVE_DOCKER=1` and named `live_*` so an ordinary
//! `cargo test` skips them: they need a daemon, pull images, and are far slower
//! than the unit suite. Everything about argument construction is covered
//! without a daemon in `src/sandbox/test.rs`; what is here is what only a real
//! daemon can answer.
//!
//! The isolation tests assert **negatively** — that the box *cannot* see the
//! host — because a positive assertion would pass just as happily against a
//! sandbox that confines nothing.
//!
//! Run them with:
//!
//! ```sh
//! TINYBOX_LIVE_DOCKER=1 cargo test -p tinybox-docker --test live_docker
//! ```

use std::sync::Arc;

use tinybox_core::{
    BoxSpec, Error, ExecRequest, Host as _, HostRef, MemoryStore, NetworkPolicy, Placement, Result,
    Sandbox, SandboxRef, WorkspaceSource,
};
use tinybox_docker::DockerSandbox;
use tinybox_host::LocalHost;

/// The image every live test uses. Small, and it ships a shell.
const IMAGE: &str = "alpine:3";

/// Whether the live suite should run at all.
fn enabled() -> bool {
    std::env::var_os("TINYBOX_LIVE_DOCKER").is_some()
}

/// A sandbox in its own namespace.
///
/// Every test allocates `box-0` from a fresh store, so without a per-test
/// namespace they would all fight over one container name on the daemon — which
/// is exactly the collision the namespace exists to prevent.
fn sandbox(namespace: &str) -> Result<DockerSandbox> {
    DockerSandbox::with_namespace(
        Arc::new(LocalHost::new()),
        Arc::new(MemoryStore::new()),
        namespace,
    )
}

fn spec_from(source: WorkspaceSource) -> Result<BoxSpec> {
    Ok(BoxSpec::new(
        Placement::new(HostRef::new("local")?, SandboxRef::new("docker")?),
        source,
    ))
}

fn spec() -> Result<BoxSpec> {
    spec_from(WorkspaceSource::OciImage(IMAGE.to_owned()))
}

/// Run `argv` in a box and return its trimmed standard output.
async fn output_of(
    sandbox: &DockerSandbox,
    id: &tinybox_core::BoxId,
    argv: &[&str],
) -> Result<String> {
    let output = sandbox.exec(id, &ExecRequest::new(argv.to_vec())).await?;
    Ok(output.stdout_lossy().trim().to_owned())
}

#[tokio::test]
async fn live_a_box_runs_a_command_in_a_real_container() -> Result<()> {
    if !enabled() {
        return Ok(());
    }
    let sandbox = sandbox("ns-abraciarc")?;
    let info = sandbox.create(&spec()?).await?;

    let result = output_of(&sandbox, &info.id, &["echo", "from-the-container"]).await;

    sandbox.destroy(&info.id).await?;
    assert_eq!(result?, "from-the-container");
    Ok(())
}

#[tokio::test]
async fn live_the_box_cannot_see_host_processes() -> Result<()> {
    if !enabled() {
        return Ok(());
    }
    let sandbox = sandbox("ns-tbcshp")?;
    let info = sandbox.create(&spec()?).await?;

    let result = output_of(
        &sandbox,
        &info.id,
        &["sh", "-c", "ls /proc | grep -c '^[0-9]*$'"],
    )
    .await;

    sandbox.destroy(&info.id).await?;

    // The host has hundreds of processes. A PID-namespaced container sees only
    // its own handful, so a large count here means the isolation is not real.
    let visible: usize = result?.parse().unwrap_or(usize::MAX);
    assert!(
        visible < 20,
        "expected a private process table, saw {visible} processes"
    );
    Ok(())
}

#[tokio::test]
async fn live_the_box_has_its_own_root_filesystem() -> Result<()> {
    if !enabled() {
        return Ok(());
    }
    let sandbox = sandbox("ns-tbhiorf")?;
    let info = sandbox.create(&spec()?).await?;

    // A file that exists on the host checkout must not be visible inside.
    let result = output_of(
        &sandbox,
        &info.id,
        &[
            "sh",
            "-c",
            "test -e /etc/alpine-release && echo alpine; test -e /home/enamakel && echo LEAKED",
        ],
    )
    .await;

    sandbox.destroy(&info.id).await?;
    let seen = result?;
    assert!(seen.contains("alpine"));
    assert!(!seen.contains("LEAKED"), "the host filesystem was visible");
    Ok(())
}

#[tokio::test]
async fn live_a_denied_network_really_is_denied() -> Result<()> {
    if !enabled() {
        return Ok(());
    }
    let sandbox = sandbox("ns-adnrid")?;
    let info = sandbox.create(&spec()?).await?;

    // With `--network none` the container has only a loopback interface.
    let result = output_of(&sandbox, &info.id, &["sh", "-c", "ip -o link | wc -l"]).await;

    sandbox.destroy(&info.id).await?;
    let interfaces: usize = result?.parse().unwrap_or(usize::MAX);
    assert_eq!(interfaces, 1, "expected loopback only");
    Ok(())
}

#[tokio::test]
async fn live_egress_is_available_when_the_policy_allows_it() -> Result<()> {
    if !enabled() {
        return Ok(());
    }
    let sandbox = sandbox("ns-eiawtpai")?;
    let info = sandbox
        .create(&spec()?.with_network(NetworkPolicy::Egress))
        .await?;

    let result = output_of(&sandbox, &info.id, &["sh", "-c", "ip -o link | wc -l"]).await;

    sandbox.destroy(&info.id).await?;
    let interfaces: usize = result?.parse().unwrap_or(0);
    assert!(interfaces > 1, "expected more than loopback");
    Ok(())
}

#[tokio::test]
async fn live_a_memory_limit_is_actually_enforced() -> Result<()> {
    if !enabled() {
        return Ok(());
    }
    let sandbox = sandbox("ns-amliae")?;
    let spec = spec()?.with_resources(tinybox_core::Resources {
        memory_bytes: 32 * 1024 * 1024,
        ..tinybox_core::Resources::DEFAULT
    });
    let info = sandbox.create(&spec).await?;

    // The sandbox declares `ResourceLimits`, so this must hold: the cgroup
    // reports the cap that was asked for.
    let result = output_of(
        &sandbox,
        &info.id,
        &["sh", "-c", "cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory/memory.limit_in_bytes"],
    )
    .await;

    sandbox.destroy(&info.id).await?;
    assert_eq!(result?, (32 * 1024 * 1024).to_string());
    Ok(())
}

#[tokio::test]
async fn live_a_local_directory_is_visible_inside_the_box() -> Result<()> {
    if !enabled() {
        return Ok(());
    }
    let dir = tempfile::tempdir().map_err(|error| Error::io("tempdir", &error))?;
    std::fs::write(dir.path().join("note.txt"), "mounted\n")
        .map_err(|error| Error::io("write", &error))?;

    let sandbox = sandbox("ns-localdir")?;
    let info = sandbox
        .create(&spec_from(WorkspaceSource::LocalDir(dir.path().into()))?)
        .await?;

    // The bind mount is also the working directory, so a bare filename resolves.
    let result = output_of(&sandbox, &info.id, &["cat", "note.txt"]).await;

    sandbox.destroy(&info.id).await?;
    assert_eq!(result?, "mounted");
    Ok(())
}

#[tokio::test]
async fn live_a_snapshot_captures_a_write_and_a_fork_starts_from_it() -> Result<()> {
    if !enabled() {
        return Ok(());
    }
    let sandbox = sandbox("ns-ascawaafsfi")?;
    let parent = sandbox.create(&spec()?).await?;

    // Write into the parent, then capture it.
    sandbox
        .exec(
            &parent.id,
            &ExecRequest::new(["sh", "-c", "echo captured > /marker"]),
        )
        .await?;
    let snapshot = sandbox.snapshot(&parent.id).await?;

    let forked = sandbox.fork(&snapshot, &spec()?).await?;

    // The fork inherits the parent's filesystem...
    let inherited = output_of(&sandbox, &forked.id, &["cat", "/marker"]).await;

    // ...and writes in the fork do not reach back into the parent.
    sandbox
        .exec(
            &forked.id,
            &ExecRequest::new(["sh", "-c", "echo fork-only > /fork-marker"]),
        )
        .await?;
    let parent_sees_fork = output_of(
        &sandbox,
        &parent.id,
        &[
            "sh",
            "-c",
            "test -e /fork-marker && echo LEAKED || echo isolated",
        ],
    )
    .await;

    sandbox.destroy(&forked.id).await?;
    sandbox.destroy(&parent.id).await?;

    assert_eq!(inherited?, "captured");
    assert_eq!(parent_sees_fork?, "isolated");
    Ok(())
}

#[tokio::test]
async fn live_a_destroyed_box_leaves_no_container_behind() -> Result<()> {
    if !enabled() {
        return Ok(());
    }
    let sandbox = sandbox("ns-adblncb")?;
    let info = sandbox.create(&spec()?).await?;
    let name = tinybox_docker::container_name(sandbox.namespace(), &info.id);

    sandbox.destroy(&info.id).await?;

    let listed = LocalHost::new()
        .run(&ExecRequest::new([
            "docker",
            "ps",
            "--all",
            "--quiet",
            "--filter",
            &format!("name=^{name}$"),
        ]))
        .await?;

    assert!(
        listed.stdout_lossy().trim().is_empty(),
        "container {name} survived destroy"
    );
    Ok(())
}

#[tokio::test]
async fn live_a_missing_image_is_reported_with_dockers_diagnostic() -> Result<()> {
    if !enabled() {
        return Ok(());
    }
    let sandbox = sandbox("ns-amiirwdd")?;

    let outcome = sandbox
        .create(&spec_from(WorkspaceSource::OciImage(
            "tinybox.invalid/no-such-image:0".to_owned(),
        ))?)
        .await;

    assert!(matches!(
        outcome,
        Err(Error::Backend {
            operation: "create the container",
            ..
        })
    ));
    Ok(())
}
