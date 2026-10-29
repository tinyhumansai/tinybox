//! A sandbox backed by NVIDIA OpenShell sandboxes.

use std::sync::Arc;

use async_trait::async_trait;
use tinybox_core::{
    BoxId, BoxInfo, BoxSpec, BoxState, Capability, Clock, ConstraintSupport, Error, ExecOutput,
    ExecRequest, Host, IsolationLevel, Result, Sandbox, SandboxCapabilities, SnapshotId,
    SnapshotSupport, Store, SystemClock,
};

mod args;

pub use args::{BOX_LABEL, NAMESPACE_LABEL, sandbox_name};

/// The name this sandbox registers under.
pub const NAME: &str = "openshell";

/// The namespace a sandbox uses when none is given.
pub const DEFAULT_NAMESPACE: &str = "default";

/// A sandbox that runs each box as an OpenShell sandbox.
///
/// # Why it drives the CLI through a [`Host`]
///
/// Every operation is an `openshell sandbox` command run through the
/// sandbox's host, not a gRPC call from this process (ADR 0004). The CLI
/// already owns the gateway's address, TLS material and workspace, so the
/// host only needs a configured `openshell` on its `PATH`.
///
/// # Requirements on the gateway
///
/// The gateway decides where a sandbox runs and how big its workspace is.
/// tinybox asks for an image, CPU and memory, labels the sandbox with its box
/// and namespace, and optionally names a policy file. Egress beyond OpenShell's
/// default-deny, credential providers, and disk size are configured on the
/// gateway, which is why this backend refuses specs that ask for them.
#[derive(Debug, Clone)]
pub struct OpenShellSandbox {
    host: Arc<dyn Host>,
    store: Arc<dyn Store>,
    clock: Arc<dyn Clock>,
    namespace: String,
    policy: Option<String>,
}

impl OpenShellSandbox {
    /// A sandbox issuing `openshell` commands through `host`, recording boxes
    /// in `store`.
    ///
    /// Uses [`DEFAULT_NAMESPACE`]. Two stores that share one gateway workspace
    /// must use [`Self::with_namespace`] with different namespaces, or their
    /// `box-0`s will claim the same sandbox name.
    #[must_use]
    pub fn new(host: Arc<dyn Host>, store: Arc<dyn Store>) -> Self {
        Self {
            host,
            store,
            clock: Arc::new(SystemClock::new()),
            namespace: DEFAULT_NAMESPACE.to_owned(),
            policy: None,
        }
    }

    /// A sandbox whose sandbox names and labels carry `namespace`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidIdentifier`] unless `namespace` is 1–32
    /// characters of lowercase ASCII letters, digits and `-`, neither starting
    /// nor ending with `-`; it becomes part of a DNS label.
    pub fn with_namespace(
        host: Arc<dyn Host>,
        store: Arc<dyn Store>,
        namespace: impl Into<String>,
    ) -> Result<Self> {
        let namespace = namespace.into();
        if !args::is_valid_namespace(&namespace) {
            return Err(Error::InvalidIdentifier {
                kind: "openshell namespace",
                value: namespace,
            });
        }
        Ok(Self {
            namespace,
            ..Self::new(host, store)
        })
    }

    /// Stamp box records with time from `clock` instead of the system clock.
    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// Create every sandbox with the OpenShell policy file at `path`.
    ///
    /// The path is read by the `openshell` CLI, so it names a file on the
    /// sandbox's host. Without one, the gateway's default policy applies.
    #[must_use]
    pub fn with_policy(mut self, path: impl Into<String>) -> Self {
        self.policy = Some(path.into());
        self
    }

    /// What this backend can do, independent of any instance.
    #[must_use]
    pub const fn declared_capabilities() -> SandboxCapabilities {
        SandboxCapabilities::new(IsolationLevel::Kernel, SnapshotSupport::None)
            .with_resource_limits()
    }

    /// Run an `openshell` command, treating a non-zero exit as a failure.
    ///
    /// A failing `openshell` call is an operation that did not happen, so it
    /// becomes an [`Error::Backend`] carrying the CLI's own diagnostic.
    async fn openshell(&self, operation: &'static str, request: ExecRequest) -> Result<String> {
        let output = self.host.run(&request).await?;
        if !output.succeeded() {
            return Err(Error::Backend {
                sandbox: NAME.to_owned(),
                operation,
                message: output.stderr_lossy().trim().to_owned(),
            });
        }
        Ok(output.stdout_lossy().trim().to_owned())
    }

    /// Delete a box's sandbox, treating "not found" as already deleted.
    async fn delete_sandbox(&self, id: &BoxId) -> Result<()> {
        let output = self
            .host
            .run(&ExecRequest::new(args::delete(&self.namespace, id)))
            .await?;
        if output.succeeded() || args::is_missing(&output.stderr_lossy()) {
            return Ok(());
        }
        Err(Error::Backend {
            sandbox: NAME.to_owned(),
            operation: "delete the sandbox",
            message: output.stderr_lossy().trim().to_owned(),
        })
    }
}

#[async_trait]
impl Sandbox for OpenShellSandbox {
    fn name(&self) -> &'static str {
        NAME
    }

    fn capabilities(&self) -> SandboxCapabilities {
        Self::declared_capabilities()
    }

    fn constraint_support(&self) -> ConstraintSupport {
        use tinybox_core::Constraint::{Cpu, Filesystem, Memory, Network};
        use tinybox_core::Enforcement::Enforced;
        ConstraintSupport::NONE
            .with(Filesystem, Enforced)
            .with(Network, Enforced)
            .with(Cpu, Enforced)
            .with(Memory, Enforced)
    }

    async fn create(&self, spec: &BoxSpec) -> Result<BoxInfo> {
        spec.validate()?;
        // Claim the record first: it is cheap, and it allocates the identifier
        // the sandbox is named after. Building the command next means a spec
        // this backend refuses leaves no sandbox, and only a record to drop.
        let info =
            tinybox_core::insert_new(self.store.as_ref(), BoxState::Ready, spec, self.clock.now())?;
        let argv = match args::create(&self.namespace, &info.id, spec, self.policy.as_deref()) {
            Ok(argv) => argv,
            Err(error) => {
                self.store.remove(&info.id)?;
                return Err(error);
            }
        };

        let mut request = ExecRequest::new(argv);
        request.env.clone_from(&spec.env);
        if let Err(error) = self.openshell("create the sandbox", request).await {
            // The gateway may have created the sandbox before the CLI failed
            // (a timeout waiting for Ready, say). Removing it keeps a failed
            // create from leaking a running pod; the record goes either way.
            let cleanup = self.delete_sandbox(&info.id).await;
            self.store.remove(&info.id)?;
            cleanup?;
            return Err(error);
        }
        Ok(info)
    }

    async fn exec(&self, id: &BoxId, request: &ExecRequest) -> Result<ExecOutput> {
        let info = self.inspect(id).await?;
        if !info.state.accepts_commands() {
            return Err(Error::InvalidState {
                id: id.as_str().to_owned(),
                actual: info.state,
                expected: BoxState::Ready,
            });
        }

        // A command that runs and fails is a result, so the raw output is
        // returned rather than being turned into a backend error. The CLI
        // exits with the remote command's own status.
        let mut exec = ExecRequest::new(args::exec(&self.namespace, id, request)?);
        exec.stdin.clone_from(&request.stdin);
        self.host.run(&exec).await
    }

    // OpenShell has no filesystem snapshot, so neither is declared and both
    // refuse; copying the workspace out instead would be the emulation rule 1
    // forbids.
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

        // Ask the gateway rather than trusting the record: a sandbox can be
        // deleted or fail behind tinybox's back, and reporting a stale `ready`
        // would send commands to a box that is gone.
        let reported = self
            .openshell(
                "inspect the sandbox",
                ExecRequest::new(args::get(&self.namespace, id)),
            )
            .await;
        info.state = match reported {
            Ok(json) => args::state_of(&json)?,
            // The record exists but the sandbox does not: a real state to
            // report rather than an error.
            Err(Error::Backend { message, .. }) if args::is_missing(&message) => {
                BoxState::Archived
            }
            Err(other) => return Err(other),
        };
        Ok(info)
    }

    async fn destroy(&self, id: &BoxId) -> Result<()> {
        // Fail on an unknown box before touching the gateway.
        self.store.get(id)?;
        self.delete_sandbox(id).await?;
        self.store.remove(id)
    }
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
