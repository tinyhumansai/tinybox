//! The backend's behaviour, exercised against a fake [`Transport`] so no agent37
//! service is needed: a create records the box under the id agent37 returns and
//! addresses every later call with it, an exec round-trips plain output,
//! snapshot and fork refuse, an invalid namespace is refused, a create whose id
//! or record cannot be kept tears the instance down, and destroy deletes then
//! removes.

use super::*;

use std::collections::{BTreeMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use tinybox_core::clock::FixedClock;
use tinybox_core::{
    BoxSpec, HostRef, MemoryStore, Placement, Retention, SandboxRef, WorkspaceSource,
};

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
    /// What `list` reports.
    listed: Vec<InstanceView>,
    list_fails: bool,
    delete_fails: bool,
    /// Statuses `inspect` reports first, one per call, before falling back to
    /// `inspect_status`.
    inspect_script: Mutex<VecDeque<String>>,
    created_bodies: Mutex<Vec<CreateBody>>,
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
            listed: Vec::new(),
            list_fails: false,
            delete_fails: false,
            inspect_script: Mutex::new(VecDeque::new()),
            created_bodies: Mutex::new(Vec::new()),
            calls: Mutex::new(Vec::new()),
        }
    }

    fn created_bodies(&self) -> Vec<CreateBody> {
        self.created_bodies
            .lock()
            .map(|bodies| bodies.clone())
            .unwrap_or_default()
    }

    fn deletes(&self) -> Vec<String> {
        self.calls()
            .into_iter()
            .filter_map(|call| call.strip_prefix("delete:").map(str::to_owned))
            .collect()
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
    async fn create(&self, body: &CreateBody) -> Result<InstanceView> {
        self.record("create".to_owned());
        if let Ok(mut bodies) = self.created_bodies.lock() {
            bodies.push(body.clone());
        }
        Ok(InstanceView::new(&self.created_id, &self.create_status))
    }

    async fn list(&self) -> Result<Vec<InstanceView>> {
        self.record("list".to_owned());
        if self.list_fails {
            return Err(Error::Backend {
                sandbox: NAME.to_owned(),
                operation: "list the instances",
                message: "agent37 returned HTTP 500".to_owned(),
            });
        }
        Ok(self.listed.clone())
    }

    async fn exec(&self, id: &str, _body: &ExecBody) -> Result<ExecResult> {
        self.record(format!("exec:{id}"));
        Ok(self.exec_result.clone())
    }

    async fn inspect(&self, id: &str) -> Result<Option<InstanceView>> {
        self.record(format!("inspect:{id}"));
        let scripted = self
            .inspect_script
            .lock()
            .ok()
            .and_then(|mut script| script.pop_front());
        Ok(scripted
            .or_else(|| self.inspect_status.clone())
            .map(|status| InstanceView::new(id, status)))
    }

    async fn delete(&self, id: &str) -> Result<()> {
        self.record(format!("delete:{id}"));
        if self.delete_fails {
            return Err(Error::Backend {
                sandbox: NAME.to_owned(),
                operation: "delete the instance",
                message: "agent37 returned HTTP 500".to_owned(),
            });
        }
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

// ---- retention: adoption, expiry, destroy ----

/// Clock time of the sandbox under test, in unix seconds.
const NOW_SECS: u64 = 1_700_000_000;
const DAY: u64 = 86_400;

fn retained(key: &str) -> Result<BoxSpec> {
    Ok(spec()?.with_retention(Retention {
        key: key.to_owned(),
        idle_sleep_secs: 900,
        delete_after_secs: 30 * DAY,
    }))
}

/// A listed instance carrying `key`, created at `created`.
fn kept(id: &str, status: &str, key: &str, created: u64, slept_at: Option<u64>) -> InstanceView {
    let mut view = InstanceView::new(id, status);
    view.created = Some(created);
    view.slept_at = slept_at;
    view.metadata = Some(BTreeMap::from([(
        api::KEY_METADATA_KEY.to_owned(),
        serde_json::Value::from(key),
    )]));
    view
}

/// A listed instance some other tenant of the workspace owns.
fn foreign(id: &str, status: &str, slept_at: Option<u64>) -> InstanceView {
    let mut view = InstanceView::new(id, status);
    view.created = Some(1);
    view.slept_at = slept_at;
    view
}

fn with_listed(listed: Vec<InstanceView>) -> Arc<FakeTransport> {
    let mut fake = FakeTransport::new();
    fake.listed = listed;
    Arc::new(fake)
}

#[tokio::test]
async fn a_retained_create_asks_agent37_to_sleep_and_stamps_the_key() -> Result<()> {
    let transport = Arc::new(FakeTransport::new());
    let (backend, _store) = sandbox(transport.clone());
    backend.create(&retained("user-42")?).await?;
    // Nothing matches, so the listing is followed by a real create.
    assert_eq!(transport.calls(), ["list", "create"]);
    let bodies = transport.created_bodies();
    assert_eq!(bodies.len(), 1);
    assert_eq!(bodies[0].auto_sleep, Some(true));
    assert_eq!(bodies[0].idle_timeout_seconds, Some(900));
    assert_eq!(
        bodies[0]
            .metadata
            .get(api::KEY_METADATA_KEY)
            .map(String::as_str),
        Some("user-42")
    );
    Ok(())
}

#[tokio::test]
async fn a_create_without_retention_never_lists_or_expires() -> Result<()> {
    let transport = with_listed(vec![kept("old", "sleeping", "x", 1, Some(1))]);
    let (backend, _store) = sandbox(transport.clone());
    backend.create(&spec()?).await?;
    assert_eq!(transport.calls(), ["create"]);
    assert_eq!(transport.created_bodies()[0].auto_sleep, None);
    Ok(())
}

#[tokio::test]
async fn a_retained_create_after_a_restart_adopts_the_existing_box() -> Result<()> {
    let transport = with_listed(vec![kept(
        "adopted01",
        "sleeping",
        "user-42",
        NOW_SECS - 5 * DAY,
        Some(NOW_SECS - DAY),
    )]);
    // A fresh store is what a restarted host has: it knows nothing of the box.
    let (backend, store) = sandbox(transport.clone());
    let info = backend.create(&retained("user-42")?).await?;
    assert_eq!(info.id.as_str(), "adopted01");
    assert_eq!(info.state, BoxState::Ready);
    assert_eq!(
        info.spec.retention.as_ref().map(|r| r.key.as_str()),
        Some("user-42")
    );
    assert_eq!(store.get(&info.id)?.id, info.id);
    // No second instance was created.
    assert_eq!(transport.calls(), ["list"]);
    // The record carries the instance's real age, not the adoption time.
    assert_eq!(
        info.created_at,
        Some(SystemTime::UNIX_EPOCH + Duration::from_secs(NOW_SECS - 5 * DAY))
    );
    Ok(())
}

#[tokio::test]
async fn the_oldest_matching_box_wins() -> Result<()> {
    let transport = with_listed(vec![
        kept("newest", "running", "user-42", 300, None),
        kept("oldest", "running", "user-42", 100, None),
        kept("middle", "running", "user-42", 200, None),
    ]);
    let (backend, _store) = sandbox(transport);
    assert_eq!(
        backend.create(&retained("user-42")?).await?.id.as_str(),
        "oldest"
    );
    Ok(())
}

#[tokio::test]
async fn another_owners_box_is_not_adopted() -> Result<()> {
    let transport = with_listed(vec![kept("theirs", "running", "user-99", 1, None)]);
    let (backend, _store) = sandbox(transport.clone());
    let info = backend.create(&retained("user-42")?).await?;
    assert_eq!(info.id.as_str(), INSTANCE_ID);
    assert!(transport.calls().contains(&"create".to_owned()));
    Ok(())
}

#[tokio::test]
async fn instances_without_a_key_are_never_deleted() -> Result<()> {
    let transport = with_listed(vec![
        foreign("not-ours-1", "sleeping", Some(1)),
        foreign("not-ours-2", "running", None),
    ]);
    let (backend, _store) = sandbox(transport.clone());
    backend.create(&retained("user-42")?).await?;
    assert!(transport.deletes().is_empty());
    Ok(())
}

#[tokio::test]
async fn only_sleeping_and_expired_boxes_are_deleted_and_never_the_adopted_one() -> Result<()> {
    let old = NOW_SECS - 31 * DAY;
    let recent = NOW_SECS - DAY;
    let transport = with_listed(vec![
        kept("expired", "sleeping", "user-7", 1, Some(old)),
        kept("still-fresh", "sleeping", "user-8", 1, Some(recent)),
        kept("old-but-awake", "running", "user-9", 1, Some(old)),
        // Expired too, but it is the box being adopted.
        kept("mine", "sleeping", "user-42", 1, Some(old)),
    ]);
    let (backend, _store) = sandbox(transport.clone());
    let info = backend.create(&retained("user-42")?).await?;
    assert_eq!(info.id.as_str(), "mine");
    assert_eq!(transport.deletes(), ["expired"]);
    Ok(())
}

#[tokio::test]
async fn expiry_also_runs_when_the_create_makes_a_new_box() -> Result<()> {
    let transport = with_listed(vec![kept(
        "expired",
        "sleeping",
        "user-7",
        1,
        Some(NOW_SECS - 31 * DAY),
    )]);
    let (backend, _store) = sandbox(transport.clone());
    backend.create(&retained("user-42")?).await?;
    assert_eq!(transport.calls(), ["list", "delete:expired", "create"]);
    Ok(())
}

#[tokio::test]
async fn a_pass_deletes_at_most_twenty_boxes() -> Result<()> {
    let old = NOW_SECS - 40 * DAY;
    let listed = (0..25)
        .map(|n| {
            kept(
                &format!("expired{n:02}"),
                "sleeping",
                "user-7",
                1,
                Some(old + n),
            )
        })
        .collect();
    let transport = with_listed(listed);
    let (backend, _store) = sandbox(transport.clone());
    backend.create(&retained("user-42")?).await?;
    assert_eq!(transport.deletes().len(), 20);
    Ok(())
}

#[tokio::test]
async fn a_failed_delete_never_fails_the_create() -> Result<()> {
    let mut fake = FakeTransport::new();
    fake.listed = vec![kept("expired", "sleeping", "user-7", 1, Some(1))];
    fake.delete_fails = true;
    let transport = Arc::new(fake);
    let (backend, _store) = sandbox(transport.clone());
    let info = backend.create(&retained("user-42")?).await?;
    assert_eq!(info.id.as_str(), INSTANCE_ID);
    assert_eq!(transport.deletes(), ["expired"]);
    Ok(())
}

#[tokio::test]
async fn a_failed_listing_fails_the_create_rather_than_minting_a_duplicate() -> Result<()> {
    let mut fake = FakeTransport::new();
    fake.list_fails = true;
    let transport = Arc::new(fake);
    let (backend, store) = sandbox(transport.clone());
    let result = backend.create(&retained("user-42")?).await;
    assert!(matches!(result, Err(Error::Backend { .. })));
    assert_eq!(transport.calls(), ["list"]);
    assert_eq!(store.list()?.len(), 0);
    Ok(())
}

#[tokio::test]
async fn a_failed_record_insert_on_an_adopted_box_keeps_the_instance() -> Result<()> {
    let transport = with_listed(vec![kept("adopted01", "running", "user-42", 1, None)]);
    let (backend, store) = sandbox(transport.clone());
    // The record is already there, so adopting it again collides in the store.
    let existing = BoxInfo::new(
        BoxId::new("adopted01")?,
        BoxState::Ready,
        retained("user-42")?,
    );
    store.insert(&existing)?;
    let result = backend.create(&retained("user-42")?).await;
    assert!(result.is_err());
    // The instance holds a user's files: it must not be deleted.
    assert!(transport.deletes().is_empty());
    Ok(())
}

#[tokio::test]
async fn destroying_a_retained_box_keeps_the_instance_and_drops_the_record() -> Result<()> {
    let transport = Arc::new(FakeTransport::new());
    let (backend, store) = sandbox(transport.clone());
    let info = backend.create(&retained("user-42")?).await?;
    backend.destroy(&info.id).await?;
    assert!(transport.deletes().is_empty());
    assert!(store.get(&info.id).is_err());
    Ok(())
}

#[tokio::test]
async fn destroying_a_box_that_was_not_retained_still_deletes_it() -> Result<()> {
    let transport = Arc::new(FakeTransport::new());
    let (backend, store) = sandbox(transport.clone());
    let info = backend.create(&spec()?).await?;
    backend.destroy(&info.id).await?;
    assert_eq!(transport.deletes(), [INSTANCE_ID]);
    assert!(store.get(&info.id).is_err());
    Ok(())
}

#[test]
fn agent37_declares_the_retention_capability() {
    assert!(Agent37Sandbox::declared_capabilities().supports(tinybox_core::Capability::Retention));
}

// ---- waking and readiness ----

fn scripted_inspects(statuses: &[&str]) -> FakeTransport {
    let mut fake = FakeTransport::new();
    fake.inspect_script = Mutex::new(statuses.iter().map(|s| (*s).to_owned()).collect());
    fake
}

#[tokio::test(start_paused = true)]
async fn exec_waits_through_a_waking_instance_before_running() -> Result<()> {
    let transport = Arc::new(scripted_inspects(&["waking", "waking", "running"]));
    let (backend, _store) = sandbox(transport.clone());
    let info = backend.create(&spec()?).await?;
    let started = tokio::time::Instant::now();
    backend
        .exec(&info.id, &ExecRequest::new(["echo", "hi"]))
        .await?;
    let inspects = transport
        .calls()
        .iter()
        .filter(|call| call.starts_with("inspect:"))
        .count();
    assert_eq!(inspects, 3);
    // The command ran only after the instance settled, and the backoff was
    // virtual time: 1s then 2s.
    assert_eq!(
        transport.calls().last(),
        Some(&format!("exec:{INSTANCE_ID}"))
    );
    assert_eq!(started.elapsed(), Duration::from_secs(3));
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn exec_waits_for_a_freshly_created_instance_that_is_still_provisioning() -> Result<()> {
    let mut fake = scripted_inspects(&["provisioning", "starting"]);
    fake.create_status = "provisioning".to_owned();
    let transport = Arc::new(fake);
    let (backend, _store) = sandbox(transport.clone());
    let info = backend.create(&spec()?).await?;
    assert_eq!(info.state, BoxState::Creating);
    backend.exec(&info.id, &ExecRequest::new(["true"])).await?;
    assert_eq!(
        transport.calls().last(),
        Some(&format!("exec:{INSTANCE_ID}"))
    );
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn exec_gives_up_on_an_instance_that_never_wakes_after_about_a_minute() -> Result<()> {
    let mut fake = FakeTransport::new();
    fake.inspect_status = Some("waking".to_owned());
    let transport = Arc::new(fake);
    let (backend, _store) = sandbox(transport.clone());
    let info = backend.create(&spec()?).await?;
    let started = tokio::time::Instant::now();
    let result = backend.exec(&info.id, &ExecRequest::new(["true"])).await;
    assert!(matches!(
        result,
        Err(Error::InvalidState {
            actual: BoxState::Creating,
            ..
        })
    ));
    assert_eq!(started.elapsed(), Duration::from_secs(60));
    // The command was never sent.
    assert!(
        !transport
            .calls()
            .iter()
            .any(|call| call.starts_with("exec:"))
    );
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn exec_on_a_sleeping_instance_runs_at_once_because_exec_wakes_it() -> Result<()> {
    let mut fake = FakeTransport::new();
    fake.inspect_status = Some("sleeping".to_owned());
    let transport = Arc::new(fake);
    let (backend, _store) = sandbox(transport.clone());
    let info = backend.create(&spec()?).await?;
    let started = tokio::time::Instant::now();
    backend.exec(&info.id, &ExecRequest::new(["true"])).await?;
    assert_eq!(started.elapsed(), Duration::ZERO);
    Ok(())
}
