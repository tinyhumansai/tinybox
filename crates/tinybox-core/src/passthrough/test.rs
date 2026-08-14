//! Tests for the passthrough sandbox.
//!
//! [`RecordingHost`] captures the [`ExecRequest`] it was handed, which is what
//! lets these tests assert on resolution — the merged environment and the
//! chosen working directory — without spawning a process. The real spawning is
//! `LocalHost`'s job and is tested in `tinybox-host`.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use async_trait::async_trait;

use super::{NAME, PassthroughSandbox};
use crate::capability::{Capability, IsolationLevel, SnapshotSupport};
use crate::error::{Error, Result};
use crate::identity::{BoxId, HostRef, SandboxRef, SnapshotId};
use crate::runtime::{BoxState, ExecOutput, ExecRequest, Host, Sandbox};
use crate::spec::{BoxSpec, Placement, Resources, WorkspaceSource};
use crate::store::{MemoryStore, Store};

/// A host that records what it was asked to run and reports success.
#[derive(Debug, Default)]
struct RecordingHost {
    seen: Mutex<Vec<ExecRequest>>,
}

impl RecordingHost {
    fn seen(&self) -> MutexGuard<'_, Vec<ExecRequest>> {
        self.seen.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn last(&self) -> Option<ExecRequest> {
        self.seen().last().cloned()
    }
}

#[async_trait]
impl Host for RecordingHost {
    fn name(&self) -> &'static str {
        "recording"
    }

    async fn run(&self, request: &ExecRequest) -> Result<ExecOutput> {
        self.seen().push(request.clone());
        Ok(ExecOutput::new(0, b"ran".to_vec(), Vec::new()))
    }
}

/// A sandbox wired to a recording host, plus a handle on that host.
fn sandbox() -> (PassthroughSandbox, Arc<RecordingHost>) {
    let host = Arc::new(RecordingHost::default());
    let sandbox = PassthroughSandbox::new(host.clone(), Arc::new(MemoryStore::new()));
    (sandbox, host)
}

fn spec_from(source: WorkspaceSource) -> Result<BoxSpec> {
    Ok(BoxSpec::new(
        Placement::new(HostRef::new("local")?, SandboxRef::new(NAME)?),
        source,
    ))
}

fn spec() -> Result<BoxSpec> {
    spec_from(WorkspaceSource::LocalDir("/srv/work".into()))
}

#[test]
fn it_admits_it_confines_nothing() {
    let (sandbox, _host) = sandbox();
    let caps = sandbox.capabilities();

    assert_eq!(sandbox.name(), "passthrough");
    assert_eq!(caps.isolation, IsolationLevel::None);
    assert_eq!(caps.snapshot, SnapshotSupport::None);
    assert!(!caps.is_suitable_for_untrusted_code());
    // Limits are declined rather than accepted and quietly ignored.
    assert!(!caps.supports(Capability::ResourceLimits));
    assert!(caps.declared().is_empty());
}

#[tokio::test]
async fn a_box_can_be_created_inspected_and_destroyed() -> Result<()> {
    let (sandbox, _host) = sandbox();

    let created = sandbox.create(&spec()?).await?;
    assert_eq!(created.id.as_str(), "box-0");
    assert_eq!(created.state, BoxState::Ready);

    assert_eq!(sandbox.inspect(&created.id).await?, created);

    sandbox.destroy(&created.id).await?;
    assert!(sandbox.inspect(&created.id).await.is_err());
    Ok(())
}

#[tokio::test]
async fn a_command_runs_in_the_workspace_directory() -> Result<()> {
    let (sandbox, host) = sandbox();
    let created = sandbox.create(&spec()?).await?;

    let output = sandbox
        .exec(&created.id, &ExecRequest::new(["echo", "hi"]))
        .await?;

    assert!(output.succeeded());
    assert_eq!(output.stdout_lossy(), "ran");

    let seen = host.last().ok_or(Error::EmptyCommand {
        sandbox: NAME.to_owned(),
    })?;
    assert_eq!(seen.argv, ["echo", "hi"]);
    assert_eq!(seen.cwd.as_deref(), Some(std::path::Path::new("/srv/work")));
    Ok(())
}

#[tokio::test]
async fn an_explicit_working_directory_overrides_the_workspace() -> Result<()> {
    let (sandbox, host) = sandbox();
    let created = sandbox.create(&spec()?).await?;

    sandbox
        .exec(
            &created.id,
            &ExecRequest::new(["pwd"]).with_cwd("/elsewhere"),
        )
        .await?;

    let seen = host.last().ok_or(Error::EmptyCommand {
        sandbox: NAME.to_owned(),
    })?;
    assert_eq!(
        seen.cwd.as_deref(),
        Some(std::path::Path::new("/elsewhere"))
    );
    Ok(())
}

#[tokio::test]
async fn a_per_command_variable_wins_over_the_box_environment() -> Result<()> {
    let (sandbox, host) = sandbox();
    let spec = spec()?.with_env("SHARED", "box").with_env("ONLY_BOX", "1");
    let created = sandbox.create(&spec).await?;

    sandbox
        .exec(
            &created.id,
            &ExecRequest::new(["env"])
                .with_env("SHARED", "command")
                .with_env("ONLY_COMMAND", "1"),
        )
        .await?;

    let seen = host.last().ok_or(Error::EmptyCommand {
        sandbox: NAME.to_owned(),
    })?;
    assert_eq!(seen.env.get("SHARED").map(String::as_str), Some("command"));
    assert_eq!(seen.env.get("ONLY_BOX").map(String::as_str), Some("1"));
    assert_eq!(seen.env.get("ONLY_COMMAND").map(String::as_str), Some("1"));
    Ok(())
}

#[tokio::test]
async fn a_command_with_no_program_is_refused() -> Result<()> {
    let (sandbox, host) = sandbox();
    let created = sandbox.create(&spec()?).await?;

    let empty: Vec<String> = Vec::new();
    assert_eq!(
        sandbox
            .exec(&created.id, &ExecRequest::new(empty))
            .await
            .err(),
        Some(Error::EmptyCommand {
            sandbox: NAME.to_owned()
        })
    );
    // Nothing reached the host.
    assert!(host.last().is_none());
    Ok(())
}

#[tokio::test]
async fn sources_it_cannot_materialize_are_refused_at_creation() -> Result<()> {
    let (sandbox, _host) = sandbox();

    for (source, kind) in [
        (
            WorkspaceSource::OciImage("alpine:3".to_owned()),
            "OCI image",
        ),
        (
            WorkspaceSource::Snapshot(SnapshotId::new("base-1")?),
            "snapshot",
        ),
        (
            WorkspaceSource::GitRepo {
                url: "https://example.invalid/repo.git".to_owned(),
                rev: "main".to_owned(),
            },
            "git repository",
        ),
    ] {
        assert_eq!(
            sandbox.create(&spec_from(source)?).await.err(),
            Some(Error::UnsupportedWorkspaceSource {
                sandbox: NAME.to_owned(),
                kind,
            })
        );
    }

    // A refused source leaves nothing behind for a later command to trip over.
    assert!(sandbox.inspect(&BoxId::new("box-0")?).await.is_err());
    Ok(())
}

#[tokio::test]
async fn snapshots_and_forking_are_refused_rather_than_approximated() -> Result<()> {
    let (sandbox, _host) = sandbox();
    let created = sandbox.create(&spec()?).await?;

    assert_eq!(
        sandbox.snapshot(&created.id).await.err(),
        Some(Error::Unsupported {
            sandbox: NAME.to_owned(),
            capability: Capability::FilesystemSnapshot,
        })
    );
    assert_eq!(
        sandbox.fork(&SnapshotId::new("any")?, &spec()?).await.err(),
        Some(Error::Unsupported {
            sandbox: NAME.to_owned(),
            capability: Capability::Fork,
        })
    );
    Ok(())
}

#[tokio::test]
async fn an_invalid_spec_never_reaches_the_store() -> Result<()> {
    let (sandbox, _host) = sandbox();
    let spec = spec()?.with_resources(Resources {
        memory_bytes: 0,
        ..Resources::DEFAULT
    });

    assert_eq!(
        sandbox.create(&spec).await.err(),
        Some(Error::ZeroResourceLimit {
            limit: "memory_bytes"
        })
    );
    assert!(sandbox.inspect(&BoxId::new("box-0")?).await.is_err());
    Ok(())
}

#[tokio::test]
async fn a_stopped_box_accepts_no_commands() -> Result<()> {
    let host = Arc::new(RecordingHost::default());
    let store = Arc::new(MemoryStore::new());
    let sandbox = PassthroughSandbox::new(host.clone(), store.clone());
    let created = sandbox.create(&spec()?).await?;

    store.set_state(&created.id, BoxState::Stopped)?;

    assert_eq!(
        sandbox
            .exec(&created.id, &ExecRequest::new(["true"]))
            .await
            .err(),
        Some(Error::InvalidState {
            id: created.id.as_str().to_owned(),
            actual: BoxState::Stopped,
            expected: BoxState::Ready,
        })
    );
    assert!(host.last().is_none());
    Ok(())
}

#[tokio::test]
async fn an_unknown_box_is_reported_rather_than_created() -> Result<()> {
    let (sandbox, _host) = sandbox();
    let missing = BoxId::new("absent")?;
    let expected = Some(Error::UnknownBox {
        id: "absent".to_owned(),
    });

    assert_eq!(sandbox.inspect(&missing).await.err(), expected);
    assert_eq!(sandbox.destroy(&missing).await.err(), expected);
    assert_eq!(
        sandbox
            .exec(&missing, &ExecRequest::new(["true"]))
            .await
            .err(),
        expected
    );
    Ok(())
}

#[tokio::test]
async fn boxes_are_numbered_in_creation_order() -> Result<()> {
    let (sandbox, _host) = sandbox();

    assert_eq!(sandbox.create(&spec()?).await?.id.as_str(), "box-0");
    assert_eq!(sandbox.create(&spec()?).await?.id.as_str(), "box-1");
    assert_eq!(sandbox.create(&spec()?).await?.id.as_str(), "box-2");
    Ok(())
}

#[tokio::test]
async fn it_is_usable_behind_a_trait_object() -> Result<()> {
    let host = Arc::new(RecordingHost::default());
    let sandbox: Box<dyn Sandbox> =
        Box::new(PassthroughSandbox::new(host, Arc::new(MemoryStore::new())));

    assert_eq!(sandbox.name(), NAME);
    assert_eq!(sandbox.create(&spec()?).await?.state, BoxState::Ready);
    Ok(())
}

#[tokio::test]
async fn a_new_box_records_when_it_was_created() -> Result<()> {
    let clock = Arc::new(crate::clock::FixedClock::at_epoch());
    let sandbox = PassthroughSandbox::with_clock(
        Arc::new(RecordingHost::default()),
        Arc::new(MemoryStore::new()),
        clock.clone(),
    );

    let first = sandbox.create(&spec()?).await?;
    clock.advance(std::time::Duration::from_secs(30));
    let second = sandbox.create(&spec()?).await?;

    // Without this, nothing can ever tell whether a box has outlived its ttl.
    assert_eq!(first.created_at, Some(std::time::SystemTime::UNIX_EPOCH));
    assert_eq!(
        second.created_at,
        Some(std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(30))
    );
    Ok(())
}
