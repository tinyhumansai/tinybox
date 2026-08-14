//! Tests for the provider traits and their request and result types.
//!
//! [`FakeSandbox`] is a complete in-memory [`Sandbox`] used to prove the trait
//! is implementable and object-safe, and to demonstrate the rule backends are
//! held to: check [`Sandbox::capabilities`] first, and refuse what is not
//! declared rather than approximating it.

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime};

use async_trait::async_trait;

use super::{BoxInfo, BoxState, ExecOutput, ExecRequest, Host, Sandbox};
use crate::capability::{Capability, IsolationLevel, SandboxCapabilities, SnapshotSupport};
use crate::error::{Error, Result};
use crate::identity::{BoxId, HostRef, SandboxRef, SnapshotId};
use crate::spec::{BoxSpec, Lifecycle, Placement, WorkspaceSource};

/// An in-memory sandbox whose capabilities are set per test.
#[derive(Debug)]
struct FakeSandbox {
    capabilities: SandboxCapabilities,
    boxes: Mutex<Vec<BoxInfo>>,
    snapshots: Mutex<Vec<SnapshotId>>,
}

impl FakeSandbox {
    fn new(capabilities: SandboxCapabilities) -> Self {
        Self {
            capabilities,
            boxes: Mutex::new(Vec::new()),
            snapshots: Mutex::new(Vec::new()),
        }
    }

    /// Borrow the box table, tolerating a poisoned lock.
    ///
    /// A test that panics mid-assertion should not turn every later lock into a
    /// second failure, so the guard is recovered rather than unwrapped.
    fn boxes(&self) -> MutexGuard<'_, Vec<BoxInfo>> {
        self.boxes.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Borrow the snapshot table, tolerating a poisoned lock.
    fn snapshots(&self) -> MutexGuard<'_, Vec<SnapshotId>> {
        self.snapshots
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn find(&self, id: &BoxId) -> Result<BoxInfo> {
        self.boxes()
            .iter()
            .find(|info| &info.id == id)
            .cloned()
            .ok_or_else(|| Error::UnknownBox {
                id: id.as_str().to_owned(),
            })
    }
}

#[async_trait]
impl Sandbox for FakeSandbox {
    fn name(&self) -> &'static str {
        "fake"
    }

    fn capabilities(&self) -> SandboxCapabilities {
        self.capabilities
    }

    async fn create(&self, spec: &BoxSpec) -> Result<BoxInfo> {
        spec.validate()?;
        let mut boxes = self.boxes();
        let id = BoxId::new(format!("box-{}", boxes.len()))?;
        let info = BoxInfo::new(id, BoxState::Ready, spec.clone());
        boxes.push(info.clone());
        Ok(info)
    }

    async fn exec(&self, id: &BoxId, request: &ExecRequest) -> Result<ExecOutput> {
        let info = self.find(id)?;
        if !info.state.accepts_commands() {
            return Err(Error::InvalidState {
                id: id.as_str().to_owned(),
                actual: info.state,
                expected: BoxState::Ready,
            });
        }
        let echoed = request.argv.join(" ");
        Ok(ExecOutput::new(0, echoed.into_bytes(), Vec::new()))
    }

    async fn snapshot(&self, id: &BoxId) -> Result<SnapshotId> {
        self.capabilities
            .require(self.name(), Capability::FilesystemSnapshot)?;
        self.find(id)?;

        let mut snapshots = self.snapshots();
        let snapshot = SnapshotId::new(format!("snap-{}", snapshots.len()))?;
        snapshots.push(snapshot.clone());
        Ok(snapshot)
    }

    async fn fork(&self, snapshot: &SnapshotId, spec: &BoxSpec) -> Result<BoxInfo> {
        self.capabilities.require(self.name(), Capability::Fork)?;

        let known = self.snapshots().contains(snapshot);
        if !known {
            return Err(Error::UnknownSnapshot {
                id: snapshot.as_str().to_owned(),
            });
        }
        self.create(spec).await
    }

    async fn inspect(&self, id: &BoxId) -> Result<BoxInfo> {
        self.find(id)
    }

    async fn destroy(&self, id: &BoxId) -> Result<()> {
        let mut boxes = self.boxes();
        let before = boxes.len();
        boxes.retain(|info| &info.id != id);
        if boxes.len() == before {
            return Err(Error::UnknownBox {
                id: id.as_str().to_owned(),
            });
        }
        Ok(())
    }
}

/// A host that reports what it was asked to run.
#[derive(Debug)]
struct FakeHost;

#[async_trait]
impl Host for FakeHost {
    fn name(&self) -> &'static str {
        "fake-host"
    }

    async fn run(&self, request: &ExecRequest) -> Result<ExecOutput> {
        let Some(program) = request.program() else {
            return Ok(ExecOutput::new(127, Vec::new(), b"empty argv".to_vec()));
        };
        Ok(ExecOutput::new(0, program.as_bytes().to_vec(), Vec::new()))
    }
}

const CONTAINER: SandboxCapabilities =
    SandboxCapabilities::new(IsolationLevel::Kernel, SnapshotSupport::Filesystem)
        .with_fork()
        .with_port_forward()
        .with_resource_limits();

/// A colocated box targeting the fake sandbox.
fn spec() -> Result<BoxSpec> {
    Ok(BoxSpec::new(
        Placement::new(HostRef::new("local")?, SandboxRef::new("fake")?),
        WorkspaceSource::OciImage("alpine:3".to_owned()),
    ))
}

#[tokio::test]
async fn a_box_can_be_created_inspected_and_destroyed() -> Result<()> {
    let sandbox = FakeSandbox::new(CONTAINER);

    let created = sandbox.create(&spec()?).await?;
    assert_eq!(created.state, BoxState::Ready);

    let inspected = sandbox.inspect(&created.id).await?;
    assert_eq!(inspected, created);

    sandbox.destroy(&created.id).await?;
    assert!(sandbox.inspect(&created.id).await.is_err());
    Ok(())
}

#[tokio::test]
async fn an_unknown_box_is_named_in_the_error() -> Result<()> {
    let sandbox = FakeSandbox::new(CONTAINER);
    let missing = BoxId::new("nope")?;

    let error = sandbox.inspect(&missing).await.err();
    assert_eq!(
        error,
        Some(Error::UnknownBox {
            id: "nope".to_owned()
        })
    );
    assert!(error.is_some_and(|error| error.to_string() == "no box with id nope"));

    assert!(sandbox.destroy(&missing).await.is_err());
    assert!(
        sandbox
            .exec(&missing, &ExecRequest::new(["true"]))
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn a_sandbox_refuses_what_it_does_not_declare() -> Result<()> {
    let sandbox = FakeSandbox::new(SandboxCapabilities::PASSTHROUGH);
    let created = sandbox.create(&spec()?).await?;

    assert_eq!(
        sandbox.snapshot(&created.id).await.err(),
        Some(Error::Unsupported {
            sandbox: "fake".to_owned(),
            capability: Capability::FilesystemSnapshot,
        })
    );

    let snapshot = SnapshotId::new("snap-0")?;
    assert_eq!(
        sandbox.fork(&snapshot, &spec()?).await.err(),
        Some(Error::Unsupported {
            sandbox: "fake".to_owned(),
            capability: Capability::Fork,
        })
    );
    Ok(())
}

#[tokio::test]
async fn a_snapshot_can_be_forked_into_an_independent_box() -> Result<()> {
    let sandbox = FakeSandbox::new(CONTAINER);
    let created = sandbox.create(&spec()?).await?;

    let snapshot = sandbox.snapshot(&created.id).await?;
    let forked = sandbox.fork(&snapshot, &spec()?).await?;

    assert_ne!(forked.id, created.id);
    assert_eq!(forked.state, BoxState::Ready);
    Ok(())
}

#[tokio::test]
async fn forking_an_unknown_snapshot_is_rejected() -> Result<()> {
    let sandbox = FakeSandbox::new(CONTAINER);
    let missing = SnapshotId::new("absent")?;

    assert_eq!(
        sandbox.fork(&missing, &spec()?).await.err(),
        Some(Error::UnknownSnapshot {
            id: "absent".to_owned()
        })
    );
    Ok(())
}

#[tokio::test]
async fn a_command_runs_in_a_ready_box() -> Result<()> {
    let sandbox = FakeSandbox::new(CONTAINER);
    let created = sandbox.create(&spec()?).await?;

    let request = ExecRequest::new(["echo", "hello"])
        .with_cwd("/workspace")
        .with_env("LANG", "C");
    let output = sandbox.exec(&created.id, &request).await?;

    assert!(output.succeeded());
    assert_eq!(output.stdout_lossy(), "echo hello");
    assert_eq!(
        request.cwd.as_deref(),
        Some(std::path::Path::new("/workspace"))
    );
    assert_eq!(request.env.get("LANG").map(String::as_str), Some("C"));
    Ok(())
}

#[tokio::test]
async fn a_stopped_box_reports_the_state_that_blocked_the_command() -> Result<()> {
    let sandbox = FakeSandbox::new(CONTAINER);
    let created = sandbox.create(&spec()?).await?;

    sandbox.boxes()[0].state = BoxState::Stopped;

    let error = sandbox
        .exec(&created.id, &ExecRequest::new(["true"]))
        .await
        .err();
    assert_eq!(
        error,
        Some(Error::InvalidState {
            id: created.id.as_str().to_owned(),
            actual: BoxState::Stopped,
            expected: BoxState::Ready,
        })
    );
    assert!(error.is_some_and(|error| error.to_string().contains("is stopped but must be ready")));
    Ok(())
}

#[tokio::test]
async fn a_sandbox_is_usable_behind_a_trait_object() -> Result<()> {
    let sandbox: Box<dyn Sandbox> = Box::new(FakeSandbox::new(CONTAINER));

    assert_eq!(sandbox.name(), "fake");
    assert_eq!(sandbox.capabilities(), CONTAINER);
    let created = sandbox.create(&spec()?).await?;
    assert_eq!(created.state, BoxState::Ready);
    Ok(())
}

#[tokio::test]
async fn a_host_runs_a_command_without_confining_it() -> Result<()> {
    let host: Box<dyn Host> = Box::new(FakeHost);

    assert_eq!(host.name(), "fake-host");
    let output = host.run(&ExecRequest::new(["uname"])).await?;
    assert!(output.succeeded());
    assert_eq!(output.stdout_lossy(), "uname");

    let empty: Vec<String> = Vec::new();
    let output = host.run(&ExecRequest::new(empty)).await?;
    assert!(!output.succeeded());
    assert_eq!(output.exit_code, 127);
    assert_eq!(output.stderr_lossy(), "empty argv");
    Ok(())
}

#[test]
fn an_exec_request_carries_an_argument_vector_not_a_command_line() {
    let request = ExecRequest::new(["sh", "-c", "echo $HOME"]);

    assert_eq!(request.argv, ["sh", "-c", "echo $HOME"]);
    assert_eq!(request.program(), Some("sh"));
    assert!(request.cwd.is_none());
    assert_eq!(request.env, BTreeMap::new());

    let empty: Vec<String> = Vec::new();
    assert_eq!(ExecRequest::new(empty).program(), None);
}

#[test]
fn output_bytes_survive_invalid_utf8() {
    let output = ExecOutput::new(1, vec![0xff, b'a'], vec![0xfe, b'b']);

    assert!(!output.succeeded());
    assert_eq!(output.stdout, [0xff, b'a']);
    assert!(output.stdout_lossy().ends_with('a'));
    assert!(output.stderr_lossy().ends_with('b'));
}

#[test]
fn box_states_report_what_they_permit() {
    assert!(BoxState::Ready.accepts_commands());
    assert!(BoxState::Running.accepts_commands());
    for state in [
        BoxState::Creating,
        BoxState::Paused,
        BoxState::Stopped,
        BoxState::Archived,
        BoxState::Failed,
    ] {
        assert!(
            !state.accepts_commands(),
            "{state} should accept no commands"
        );
    }

    assert!(BoxState::Ready.is_live());
    assert!(!BoxState::Archived.is_live());
}

#[test]
fn every_box_state_renders_for_error_messages() {
    for (state, text) in [
        (BoxState::Creating, "creating"),
        (BoxState::Ready, "ready"),
        (BoxState::Running, "running"),
        (BoxState::Paused, "paused"),
        (BoxState::Stopped, "stopped"),
        (BoxState::Archived, "archived"),
        (BoxState::Failed, "failed"),
    ] {
        assert_eq!(state.to_string(), text);
    }
}

#[test]
fn only_an_ephemeral_box_expires() -> Result<()> {
    let created = SystemTime::UNIX_EPOCH;
    let ephemeral = BoxInfo::new(
        BoxId::new("box-0")?,
        BoxState::Ready,
        spec()?.with_lifecycle(Lifecycle::Ephemeral {
            ttl: Duration::from_secs(60),
        }),
    )
    .created_at(created);
    let persistent = BoxInfo::new(
        BoxId::new("box-1")?,
        BoxState::Ready,
        spec()?.with_lifecycle(Lifecycle::persistent()),
    )
    .created_at(created);

    assert_eq!(
        ephemeral.expires_at(),
        Some(created + Duration::from_secs(60))
    );
    // A workspace someone is using must not disappear on a timer.
    assert_eq!(persistent.expires_at(), None);
    assert!(!persistent.is_expired(created + Duration::from_secs(86_400)));
    Ok(())
}

#[test]
fn expiry_happens_at_the_deadline_not_before() -> Result<()> {
    let created = SystemTime::UNIX_EPOCH;
    let info = BoxInfo::new(
        BoxId::new("box-0")?,
        BoxState::Ready,
        spec()?.with_lifecycle(Lifecycle::Ephemeral {
            ttl: Duration::from_secs(60),
        }),
    )
    .created_at(created);

    assert!(!info.is_expired(created));
    assert!(!info.is_expired(created + Duration::from_secs(59)));
    assert!(info.is_expired(created + Duration::from_secs(60)));
    assert!(info.is_expired(created + Duration::from_secs(61)));
    Ok(())
}

#[test]
fn a_box_with_no_recorded_creation_time_never_expires() -> Result<()> {
    // Exactly what a store written before tinybox tracked time contains.
    // Guessing an age here would destroy somebody's work on the strength of a
    // missing field.
    let info = BoxInfo::new(
        BoxId::new("box-0")?,
        BoxState::Ready,
        spec()?.with_lifecycle(Lifecycle::Ephemeral {
            ttl: Duration::from_secs(1),
        }),
    );

    assert_eq!(info.created_at, None);
    assert_eq!(info.expires_at(), None);
    assert!(!info.is_expired(SystemTime::UNIX_EPOCH + Duration::from_secs(86_400)));
    Ok(())
}
