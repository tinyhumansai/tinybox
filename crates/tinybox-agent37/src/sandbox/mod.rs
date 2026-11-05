//! A sandbox that runs each box as an agent37 instance over HTTP.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use tinybox_core::{
    BoxId, BoxInfo, BoxSpec, BoxState, Capability, Clock, ConstraintSupport, Error, ExecOutput,
    ExecRequest, IsolationLevel, Result, Retention, Sandbox, SandboxCapabilities, SnapshotId,
    SnapshotSupport, Store, SystemClock,
};

use crate::api::{self, InstanceView};
use crate::retention;
use crate::transport::Transport;

/// The name this sandbox registers under.
pub const NAME: &str = "agent37";

/// The namespace stamped onto an instance's metadata when none is given.
pub const DEFAULT_NAMESPACE: &str = "default";

/// How long [`Sandbox::exec`] waits before each re-inspection of an instance
/// that is still provisioning, starting or waking: 60 s in all. After that the
/// instance is reported in the state it is in rather than waited on forever.
const SETTLE_BACKOFF: [Duration; 7] = [
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(4),
    Duration::from_secs(8),
    Duration::from_secs(15),
    Duration::from_secs(15),
    Duration::from_secs(15),
];

/// The process-wide lock serializing lookup-and-create for one retained owner
/// key within a namespace.
fn owner_gate(namespace: &str, key: &str) -> Arc<tokio::sync::Mutex<()>> {
    static GATES: std::sync::LazyLock<
        std::sync::Mutex<std::collections::HashMap<(String, String), Arc<tokio::sync::Mutex<()>>>>,
    > = std::sync::LazyLock::new(Default::default);
    let mut gates = GATES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    gates
        .entry((namespace.to_owned(), key.to_owned()))
        .or_default()
        .clone()
}

/// A sandbox that runs each box as an agent37 instance.
///
/// It holds an agent37 [`Transport`] (the HTTP client), a [`Store`] for box
/// records, and a [`Clock`] for their timestamps. agent37 mints the instance
/// id on create, so the box is recorded under that id and every later call
/// (exec, inspect, destroy) addresses the instance with it directly — there is
/// no client-derived name or stored mapping. The namespace is carried only as
/// instance metadata, for observability.
///
/// # Retained boxes
///
/// A spec with [`Retention`] makes the box one an owner keeps across uses. It
/// is created with agent37's auto-sleep on, so an idle box costs disk only and
/// the next command wakes it. Its owner key is stored in the instance's
/// metadata, so a later [`create`](Sandbox::create) with the same key — even
/// from a restarted host whose store is empty — lists the workspace and
/// *adopts* the existing instance instead of making another. The same pass
/// deletes retained instances that have slept longer than
/// [`Retention::delete_after_secs`], which is the only way a retained box ends:
/// [`destroy`](Sandbox::destroy) forgets the local record and leaves the
/// instance (and the owner's files) in place.
#[derive(Debug, Clone)]
pub struct Agent37Sandbox {
    transport: Arc<dyn Transport>,
    store: Arc<dyn Store>,
    clock: Arc<dyn Clock>,
    namespace: String,
}

impl Agent37Sandbox {
    /// A sandbox issuing agent37 requests through `transport`, recording boxes
    /// in `store`, under [`DEFAULT_NAMESPACE`].
    #[must_use]
    pub fn new(transport: Arc<dyn Transport>, store: Arc<dyn Store>) -> Self {
        Self {
            transport,
            store,
            clock: Arc::new(SystemClock::new()),
            namespace: DEFAULT_NAMESPACE.to_owned(),
        }
    }

    /// A sandbox whose instance metadata carries `namespace`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidIdentifier`] unless `namespace` is 1–49 characters of
    /// lowercase ASCII letters, digits and `-`, neither starting nor ending
    /// with `-`.
    pub fn with_namespace(
        transport: Arc<dyn Transport>,
        store: Arc<dyn Store>,
        namespace: impl Into<String>,
    ) -> Result<Self> {
        let namespace = namespace.into();
        if !is_valid_namespace(&namespace) {
            return Err(Error::InvalidIdentifier {
                kind: "agent37 namespace",
                value: namespace,
            });
        }
        Ok(Self {
            namespace,
            ..Self::new(transport, store)
        })
    }

    /// Stamp box records with time from `clock` instead of the system clock.
    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// What this backend can do, independent of any instance.
    #[must_use]
    pub const fn declared_capabilities() -> SandboxCapabilities {
        SandboxCapabilities::new(IsolationLevel::Kernel, SnapshotSupport::None).with_retention()
    }

    /// Record `view` as the box for `spec`, keeping the instance whatever
    /// happens: an adopted instance holds an owner's files, so no failure here
    /// may delete it.
    fn record_adopted(&self, view: &InstanceView, spec: &BoxSpec) -> Result<BoxInfo> {
        let id = BoxId::new(view.id.clone())?;
        let created_at = view.created.map_or_else(
            || self.clock.now(),
            |secs| SystemTime::UNIX_EPOCH + Duration::from_secs(secs),
        );
        let info = BoxInfo::new(id, view.state(), spec.clone()).created_at(created_at);
        match self.store.insert(&info) {
            // The store outlives the host, and a crash skips destroy, so the
            // record of a box being adopted again may still be there.
            Err(Error::DuplicateBox { .. }) => {
                self.store.remove(&info.id)?;
                self.store.insert(&info)?;
            }
            other => other?,
        }
        Ok(info)
    }

    /// List the workspace, delete retained boxes that expired, and return the
    /// existing box for `retention.key` when there is one.
    ///
    /// A failed delete is ignored — the instance is picked up again by the next
    /// pass — but a failed listing is an error: creating anyway could mint a
    /// second box for an owner whose first one is merely unreachable.
    async fn adopt(&self, spec: &BoxSpec, retention: &Retention) -> Result<Option<BoxInfo>> {
        let listed = self.transport.list().await?;
        let now_secs = self
            .clock
            .now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs());
        let plan = retention::plan(
            &listed,
            &retention.key,
            now_secs,
            retention.delete_after_secs,
        );
        for id in &plan.expired {
            let _ = self.transport.delete(id).await;
        }
        plan.adopt
            .map(|view| self.record_adopted(&view, spec))
            .transpose()
    }

    /// Inspect `id`, re-inspecting with backoff while it is still
    /// provisioning, starting or waking so a command is not sent to an
    /// instance that cannot take it yet.
    async fn inspect_settled(&self, id: &BoxId) -> Result<BoxInfo> {
        let mut info = self.inspect(id).await?;
        for delay in SETTLE_BACKOFF {
            if info.state != BoxState::Creating {
                break;
            }
            tokio::time::sleep(delay).await;
            info = self.inspect(id).await?;
        }
        Ok(info)
    }
}

#[async_trait]
impl Sandbox for Agent37Sandbox {
    fn name(&self) -> &'static str {
        NAME
    }

    fn capabilities(&self) -> SandboxCapabilities {
        Self::declared_capabilities()
    }

    fn constraint_support(&self) -> ConstraintSupport {
        use tinybox_core::Constraint::{Cpu, Disk, Filesystem, Memory, Network};
        use tinybox_core::Enforcement::{BestEffort, Enforced};
        // Filesystem and network are hard: each instance is kernel-isolated and
        // created `deny-all`, and a non-`Denied` spec is refused. CPU, memory
        // and disk are advisory: agent37 offers fixed shapes and caps CPU, so
        // the exact requested limit is not guaranteed.
        ConstraintSupport::NONE
            .with(Filesystem, Enforced)
            .with(Network, Enforced)
            .with(Cpu, BestEffort)
            .with(Memory, BestEffort)
            .with(Disk, BestEffort)
    }

    async fn create(&self, spec: &BoxSpec) -> Result<BoxInfo> {
        spec.validate()?;
        // Refuse an unsupported spec before touching agent37, so a refusal
        // leaves no instance.
        let body = api::create_body(&self.namespace, spec)?;
        // Lookup and create for one owner key must not interleave: two creates
        // that both list before either creates would mint two instances for one
        // owner. Sandboxes are built per resource, so the gate is process-wide.
        let _gate = match &spec.retention {
            Some(retention) => Some(owner_gate(&self.namespace, &retention.key).lock_owned().await),
            None => None,
        };
        if let Some(retention) = &spec.retention
            && let Some(info) = self.adopt(spec, retention).await?
        {
            return Ok(info);
        }
        // agent37 mints the id, so the instance is created first and the record
        // is keyed by the id it returns.
        let view = self.transport.create(&body).await?;
        let id = match BoxId::new(view.id.clone()) {
            Ok(id) => id,
            Err(error) => {
                // An id tinybox cannot represent would orphan the instance, so
                // tear it down before surfacing the error.
                let _ = self.transport.delete(&view.id).await;
                return Err(error);
            }
        };
        let info = BoxInfo::new(id, api::box_state_from_status(&view.status), spec.clone())
            .created_at(self.clock.now());
        if let Err(error) = self.store.insert(&info) {
            // The instance exists but we could not record it; delete it so a
            // failed create does not leak a running instance.
            let _ = self.transport.delete(info.id.as_str()).await;
            return Err(error);
        }
        Ok(info)
    }

    async fn exec(&self, id: &BoxId, request: &ExecRequest) -> Result<ExecOutput> {
        let info = self.inspect_settled(id).await?;
        if !info.state.accepts_commands() {
            return Err(Error::InvalidState {
                id: id.as_str().to_owned(),
                actual: info.state,
                expected: BoxState::Ready,
            });
        }
        // A command that runs and fails is a result, so the raw output is
        // returned rather than becoming a backend error.
        let result = self
            .transport
            .exec(id.as_str(), &api::exec_body(request))
            .await?;
        Ok(api::exec_output(&result))
    }

    // agent37 exposes no filesystem snapshot, so neither is declared and both
    // refuse rather than emulating (tinybox rule 1).
    async fn snapshot(&self, _id: &BoxId) -> Result<SnapshotId> {
        Err(Error::Unsupported {
            sandbox: NAME.to_owned(),
            capability: Capability::FilesystemSnapshot,
        })
    }

    async fn fork(&self, _snapshot: &SnapshotId, _spec: &BoxSpec) -> Result<BoxInfo> {
        Err(Error::Unsupported {
            sandbox: NAME.to_owned(),
            capability: Capability::Fork,
        })
    }

    async fn inspect(&self, id: &BoxId) -> Result<BoxInfo> {
        let mut info = self.store.get(id)?;
        // Ask agent37 rather than trusting the record: an instance can be
        // deleted or fail behind tinybox's back, and reporting a stale `ready`
        // would send commands to an instance that is gone.
        info.state = match self.transport.inspect(id.as_str()).await? {
            Some(view) => api::box_state_from_status(&view.status),
            // The record exists but the instance does not: a real state, not an
            // error.
            None => BoxState::Archived,
        };
        Ok(info)
    }

    async fn destroy(&self, id: &BoxId) -> Result<()> {
        // Fail on an unknown box before calling agent37.
        let info = self.store.get(id)?;
        // A retained box outlives its handle: closing it on idle or at shutdown
        // must keep the owner's files, so only the local record goes and the
        // retention pass deletes the instance once it has slept long enough.
        if info.spec.retention.is_none() {
            self.transport.delete(id.as_str()).await?;
        }
        self.store.remove(id)
    }
}

/// A valid agent37 namespace: 1–49 chars of `[a-z0-9-]`, not edged with `-`.
fn is_valid_namespace(namespace: &str) -> bool {
    let bytes = namespace.as_bytes();
    (1..=49).contains(&bytes.len())
        && !namespace.starts_with('-')
        && !namespace.ends_with('-')
        && namespace
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
