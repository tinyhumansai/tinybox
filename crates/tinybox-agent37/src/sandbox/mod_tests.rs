//! The backend's behaviour, exercised against a fake [`Transport`] so no agent37
//! service is needed: a create records the box under the id agent37 returns and
//! addresses every later call with it, an exec round-trips plain output,
//! snapshot and fork refuse, an invalid namespace is refused, a create whose id
//! or record cannot be kept tears the instance down, and destroy deletes then
//! removes.

use super::*;

use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use tinybox_core::clock::FixedClock;
use tinybox_core::{BoxSpec, HostRef, MemoryStore, Placement, SandboxRef, WorkspaceSource};

use crate::api::{CreateBody, ExecBody, ExecResult, InstanceView};

/// The id the fake agent37 mints on create.
const INSTANCE_ID: &str = "ab12cd34ef";

/// A [`Transport`] that answers from fixed values and records each call, with
/// the instance id so a test can prove the backend addresses it correctly.
#[derive(Debug)]
struct FakeTransport {
    created_id: String,
    create_status: String,
    inspect_status: Option<String>,
    exec_result: ExecResult,
    calls: Mutex<Vec<String>>,
}

impl FakeTransport {
    fn new() -> Self {
        Self {
            created_id: INSTANCE_ID.to_owned(),
            create_status: "running".to_owned(),
            inspect_status: Some("running".to_owned()),
            exec_result: ExecResult {
                exit_code: 0,
                stdout: String::new(),
                stderr: String::new(),
                truncated: false,
            },
            calls: Mutex::new(Vec::new()),
        }
    }

    fn record(&self, call: String) {
        if let Ok(mut calls) = self.calls.lock() {
            calls.push(call);
        }
    }

    fn calls(&self) -> Vec<String> {
        self.calls
            .lock()
            .map(|calls| calls.clone())
            .unwrap_or_default()
    }
}

#[async_trait]
impl Transport for FakeTransport {
    async fn create(&self, _body: &CreateBody) -> Result<InstanceView> {
        self.record("create".to_owned());
        Ok(InstanceView {
            id: self.created_id.clone(),
            status: self.create_status.clone(),
        })
    }

    async fn exec(&self, id: &str, _body: &ExecBody) -> Result<ExecResult> {
        self.record(format!("exec:{id}"));
        Ok(self.exec_result.clone())
    }

    async fn inspect(&self, id: &str) -> Result<Option<InstanceView>> {
        self.record(format!("inspect:{id}"));
        Ok(self.inspect_status.clone().map(|status| InstanceView {
            id: id.to_owned(),
            status,
        }))
    }

    async fn delete(&self, id: &str) -> Result<()> {
        self.record(format!("delete:{id}"));
        Ok(())
    }
}

fn spec() -> Result<BoxSpec> {
    Ok(BoxSpec::new(
        Placement::new(HostRef::new("local")?, SandboxRef::new(NAME)?),
        WorkspaceSource::OciImage("agent37-base".to_owned()),
    ))
}

fn sandbox(transport: Arc<FakeTransport>) -> (Agent37Sandbox, Arc<MemoryStore>) {
    let store = Arc::new(MemoryStore::new());
    let at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let backend =
        Agent37Sandbox::new(transport, store.clone()).with_clock(Arc::new(FixedClock::at(at)));
    (backend, store)
}

#[tokio::test]
async fn create_records_the_box_under_the_agent37_id() -> Result<()> {
    let transport = Arc::new(FakeTransport::new());
    let (backend, store) = sandbox(transport.clone());
    let info = backend.create(&spec()?).await?;
    assert_eq!(transport.calls(), ["create"]);
    // The box id is the id agent37 minted, and the record exists under it.
    assert_eq!(info.id.as_str(), INSTANCE_ID);
    assert_eq!(store.get(&info.id)?.id, info.id);
    Ok(())
}

#[tokio::test]
async fn exec_round_trips_plain_output_addressed_by_the_instance_id() -> Result<()> {
    let mut fake = FakeTransport::new();
    fake.exec_result = ExecResult {
        exit_code: 7,
        stdout: "hi".to_owned(),
        stderr: String::new(),
        truncated: false,
    };
    let transport = Arc::new(fake);
    let (backend, _store) = sandbox(transport.clone());
    let info = backend.create(&spec()?).await?;
    let output = backend
        .exec(&info.id, &ExecRequest::new(["echo", "hi"]))
        .await?;
    assert_eq!(output.exit_code, 7);
    assert_eq!(output.stdout, b"hi");
    // exec inspects the box first, then runs the command, both by instance id.
    assert_eq!(
        transport.calls(),
        [
            "create".to_owned(),
            format!("inspect:{INSTANCE_ID}"),
            format!("exec:{INSTANCE_ID}"),
        ]
    );
    Ok(())
}

#[tokio::test]
async fn an_invalid_namespace_is_refused() {
    let transport: Arc<dyn Transport> = Arc::new(FakeTransport::new());
    let refused =
        Agent37Sandbox::with_namespace(transport, Arc::new(MemoryStore::new()), "Not_Valid");
    assert!(matches!(refused, Err(Error::InvalidIdentifier { .. })));
}

#[tokio::test]
async fn snapshot_and_fork_are_unsupported() -> Result<()> {
    let (backend, _store) = sandbox(Arc::new(FakeTransport::new()));
    let info = backend.create(&spec()?).await?;
    assert!(matches!(
        backend.snapshot(&info.id).await,
        Err(Error::Unsupported { .. })
    ));
    Ok(())
}

#[tokio::test]
async fn an_unrepresentable_id_tears_the_instance_down() -> Result<()> {
    let mut fake = FakeTransport::new();
    // A space is not a valid tinybox identifier.
    fake.created_id = "bad id".to_owned();
    let transport = Arc::new(fake);
    let (backend, _store) = sandbox(transport.clone());
    let result = backend.create(&spec()?).await;
    assert!(matches!(result, Err(Error::InvalidIdentifier { .. })));
    // The orphaned instance was deleted.
    assert_eq!(
        transport.calls(),
        ["create".to_owned(), "delete:bad id".to_owned()]
    );
    Ok(())
}

#[tokio::test]
async fn a_record_that_cannot_be_kept_deletes_the_instance() -> Result<()> {
    let transport = Arc::new(FakeTransport::new());
    let (backend, _store) = sandbox(transport.clone());
    // The first create records the box; the second gets the same id from the
    // fake, so the record insert collides and the new instance is torn down.
    backend.create(&spec()?).await?;
    let result = backend.create(&spec()?).await;
    assert!(result.is_err());
    assert!(transport.calls().contains(&format!("delete:{INSTANCE_ID}")));
    Ok(())
}

#[tokio::test]
async fn destroy_deletes_the_instance_and_removes_the_record() -> Result<()> {
    let transport = Arc::new(FakeTransport::new());
    let (backend, store) = sandbox(transport.clone());
    let info = backend.create(&spec()?).await?;
    backend.destroy(&info.id).await?;
    assert!(transport.calls().contains(&format!("delete:{INSTANCE_ID}")));
    // The record is gone.
    assert!(store.get(&info.id).is_err());
    Ok(())
}

#[tokio::test]
async fn with_namespace_accepts_a_valid_namespace() -> Result<()> {
    let transport = Arc::new(FakeTransport::new());
    let backend = Agent37Sandbox::with_namespace(
        transport.clone(),
        Arc::new(MemoryStore::new()),
        "acme-prod-1",
    )?;
    // The namespace-carrying sandbox still creates a box.
    backend.create(&spec()?).await?;
    assert_eq!(transport.calls(), ["create"]);
    Ok(())
}

#[test]
fn it_reports_its_name_capabilities_and_constraint_support() {
    let (backend, _store) = sandbox(Arc::new(FakeTransport::new()));
    assert_eq!(backend.name(), NAME);
    // Capabilities come from the static declaration; kernel isolation, no
    // snapshots.
    assert_eq!(
        backend.capabilities(),
        Agent37Sandbox::declared_capabilities()
    );
    assert_eq!(
        Agent37Sandbox::declared_capabilities(),
        SandboxCapabilities::new(IsolationLevel::Kernel, SnapshotSupport::None)
    );
    // Exercise the constraint-support declaration (filesystem/network enforced,
    // cpu/memory/disk best-effort).
    let _support = backend.constraint_support();
}

#[tokio::test]
async fn fork_is_unsupported() -> Result<()> {
    let (backend, _store) = sandbox(Arc::new(FakeTransport::new()));
    let snapshot = SnapshotId::new("snap-1")?;
    assert!(matches!(
        backend.fork(&snapshot, &spec()?).await,
        Err(Error::Unsupported { .. })
    ));
    Ok(())
}

#[tokio::test]
async fn exec_on_a_stopped_instance_is_an_invalid_state_error() -> Result<()> {
    let mut fake = FakeTransport::new();
    // The box records fine on create, but inspect then reports it stopped, so
    // exec must refuse rather than send a command to a box that is down.
    fake.inspect_status = Some("stopped".to_owned());
    let transport = Arc::new(fake);
    let (backend, _store) = sandbox(transport);
    let info = backend.create(&spec()?).await?;
    assert!(matches!(
        backend
            .exec(&info.id, &ExecRequest::new(["echo", "hi"]))
            .await,
        Err(Error::InvalidState { .. })
    ));
    Ok(())
}
