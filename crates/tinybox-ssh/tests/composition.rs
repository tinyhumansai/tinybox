//! The ADR 0002 and ADR 0004 claims, tested rather than asserted.
//!
//! ADR 0002 said reach and confinement are orthogonal, so `ssh` + `docker`
//! would be Docker on a remote machine at no cost. ADR 0004 said driving the
//! `docker` CLI through a [`Host`] rather than a local socket is what would
//! make that true in practice.
//!
//! This file is the receipt. `tinybox-docker` was written before `tinybox-ssh`
//! existed and has not been touched since; if these pass, the composition
//! really did cost nothing.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use async_trait::async_trait;
use tinybox_core::{
    BoxSpec, ExecOutput, ExecRequest, Host, HostRef, MemoryStore, PassthroughSandbox, Placement,
    Result, Sandbox, SandboxRef, WorkspaceSource,
};
use tinybox_docker::DockerSandbox;
use tinybox_ssh::{SshHost, SshTarget};

/// Stands in for the local machine, recording what it is asked to run.
#[derive(Debug, Default)]
struct RecordingHost {
    seen: Mutex<Vec<Vec<String>>>,
}

impl RecordingHost {
    fn seen(&self) -> MutexGuard<'_, Vec<Vec<String>>> {
        self.seen.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The single command line the far side was asked to run.
    fn remote_command(&self) -> String {
        self.seen()
            .first()
            .and_then(|argv| argv.last().cloned())
            .unwrap_or_default()
    }

    fn argv(&self) -> Vec<String> {
        self.seen().first().cloned().unwrap_or_default()
    }
}

#[async_trait]
impl Host for RecordingHost {
    fn name(&self) -> &'static str {
        "recording"
    }

    async fn run(&self, request: &ExecRequest) -> Result<ExecOutput> {
        self.seen().push(request.argv.clone());
        // `docker inspect` asks for a status; anything else is content-free.
        Ok(ExecOutput::new(0, b"running".to_vec(), Vec::new()))
    }
}

/// A Docker sandbox whose reach is an SSH connection, plus the local machine.
fn remote_docker() -> Result<(DockerSandbox, Arc<RecordingHost>)> {
    let local = Arc::new(RecordingHost::default());
    let remote = Arc::new(SshHost::new(
        local.clone(),
        SshTarget::new("builder@example.invalid")?,
    ));
    Ok((
        DockerSandbox::new(remote, Arc::new(MemoryStore::new())),
        local,
    ))
}

fn spec(sandbox: &str) -> Result<BoxSpec> {
    Ok(BoxSpec::new(
        Placement::new(HostRef::new("builder")?, SandboxRef::new(sandbox)?),
        WorkspaceSource::OciImage("alpine:3".to_owned()),
    ))
}

#[tokio::test]
async fn creating_a_docker_box_over_ssh_runs_docker_on_the_far_machine() -> Result<()> {
    let (sandbox, local) = remote_docker()?;

    sandbox.create(&spec("docker")?).await?;

    // The local machine ran `ssh`, not `docker`...
    let argv = local.argv();
    assert_eq!(argv.first().map(String::as_str), Some("ssh"));
    assert!(argv.contains(&"builder@example.invalid".to_owned()));

    // ...and `docker run` is what the far machine was asked to do.
    let remote = local.remote_command();
    assert!(remote.starts_with("'docker' 'run'"), "{remote}");
    assert!(remote.contains("'alpine:3'"), "{remote}");
    Ok(())
}

#[tokio::test]
async fn the_container_name_and_limits_survive_the_crossing() -> Result<()> {
    let (sandbox, local) = remote_docker()?;

    sandbox.create(&spec("docker")?).await?;

    let remote = local.remote_command();
    // Every flag the Docker backend built is intact on the other side, each as
    // its own quoted word rather than run together.
    assert!(
        remote.contains("'--name' 'tinybox-default-box-0'"),
        "{remote}"
    );
    assert!(remote.contains("'--memory'"), "{remote}");
    assert!(remote.contains("'--pids-limit' '512'"), "{remote}");
    assert!(remote.contains("'--network' 'none'"), "{remote}");
    Ok(())
}

#[tokio::test]
async fn the_keepalive_command_is_not_mangled_by_two_shells() -> Result<()> {
    let (sandbox, local) = remote_docker()?;

    sandbox.create(&spec("docker")?).await?;

    // This is the case a naive implementation gets wrong: the keepalive is
    // itself a shell command, so it crosses one shell (ssh's) on its way to
    // being an argument to another (the container's). It must arrive whole.
    let remote = local.remote_command();
    assert!(
        remote.contains(r"'while :; do sleep 86400; done'"),
        "{remote}"
    );
    Ok(())
}

#[tokio::test]
async fn a_command_in_a_remote_container_crosses_both_boundaries() -> Result<()> {
    let (sandbox, local) = remote_docker()?;
    let info = sandbox.create(&spec("docker")?).await?;
    local.seen().clear();

    sandbox
        .exec(&info.id, &ExecRequest::new(["echo", "hello world"]))
        .await?;

    // The first command after create is the inspect that checks the container
    // is running; the shape is what matters here.
    let argv = local.argv();
    assert_eq!(argv.first().map(String::as_str), Some("ssh"));
    assert!(local.remote_command().starts_with("'docker'"));
    Ok(())
}

#[tokio::test]
async fn an_argument_with_shell_metacharacters_reaches_the_container_intact() -> Result<()> {
    let (sandbox, local) = remote_docker()?;
    let info = sandbox.create(&spec("docker")?).await?;
    local.seen().clear();

    sandbox
        .exec(&info.id, &ExecRequest::new(["echo", "; rm -rf /"]))
        .await?;

    // Two shells stand between the caller and the command, and neither may act
    // on this. It is one quoted word to the remote shell, and Docker then hands
    // it to the container as a single argv entry.
    let remote = local
        .seen()
        .last()
        .and_then(|argv| argv.last().cloned())
        .unwrap_or_default();
    assert!(remote.contains(r"'; rm -rf /'"), "{remote}");
    Ok(())
}

#[tokio::test]
async fn destroying_a_remote_box_removes_the_remote_container() -> Result<()> {
    let (sandbox, local) = remote_docker()?;
    let info = sandbox.create(&spec("docker")?).await?;
    local.seen().clear();

    sandbox.destroy(&info.id).await?;

    let remote = local.remote_command();
    assert!(remote.starts_with("'docker' 'rm'"), "{remote}");
    Ok(())
}

#[tokio::test]
async fn passthrough_composes_with_ssh_too() -> Result<()> {
    let local = Arc::new(RecordingHost::default());
    let remote = Arc::new(SshHost::new(local.clone(), SshTarget::new("machine")?));
    let sandbox = PassthroughSandbox::new(remote, Arc::new(MemoryStore::new()));

    let info = sandbox
        .create(&BoxSpec::new(
            Placement::new(HostRef::new("machine")?, SandboxRef::new("passthrough")?),
            WorkspaceSource::LocalDir("/srv/work".into()),
        ))
        .await?;
    sandbox.exec(&info.id, &ExecRequest::new(["pwd"])).await?;

    // "Run it over there, unconfined" — a pairing nothing in the codebase
    // names, and which needed no passthrough-side code either.
    assert_eq!(local.remote_command(), "cd '/srv/work' && 'pwd'");
    Ok(())
}
