//! A tinybox sandbox backed by Docker containers.
//!
//! This is the first backend that actually confines anything: it declares
//! [`IsolationLevel::Kernel`](tinybox_core::IsolationLevel::Kernel), so unlike
//! passthrough it is a defensible place to run code the operator does not
//! trust.
//!
//! # It drives `docker` through a [`Host`](tinybox_core::Host)
//!
//! Every operation is a `docker` command issued through the sandbox's host
//! rather than a call to a local daemon socket. Pairing this sandbox with an
//! SSH host therefore yields Docker on a remote machine with no code dedicated
//! to that combination, and no socket forwarding. ADR 0004 records the tradeoff
//! that comes with it.
//!
//! ```no_run
//! use std::sync::Arc;
//! use tinybox_core::{BoxSpec, HostRef, MemoryStore, Placement, Sandbox, SandboxRef, WorkspaceSource};
//! use tinybox_docker::DockerSandbox;
//! use tinybox_host::LocalHost;
//!
//! # async fn run() -> tinybox_core::Result<()> {
//! let sandbox = DockerSandbox::new(Arc::new(LocalHost::new()), Arc::new(MemoryStore::new()));
//! assert!(sandbox.capabilities().is_suitable_for_untrusted_code());
//!
//! let spec = BoxSpec::new(
//!     Placement::new(HostRef::new("local")?, SandboxRef::new("docker")?),
//!     WorkspaceSource::OciImage("alpine:3".into()),
//! );
//! let info = sandbox.create(&spec).await?;
//! sandbox.destroy(&info.id).await?;
//! # Ok(())
//! # }
//! ```

mod egress;
mod egress_enforcement;
mod oneshot;
mod policy;
mod sandbox;

pub use oneshot::{
    DEFAULT_ONE_SHOT_CPUS, DEFAULT_ONE_SHOT_IMAGE, DEFAULT_ONE_SHOT_MEMORY_MB,
    DEFAULT_ONE_SHOT_NETWORK, DockerCli, MAX_OUTPUT_BYTES, ONE_SHOT_WORKSPACE, OneShot,
    OneShotOutcome,
};

pub use policy::{DANGEROUS_MOUNTS, HOST_NETWORK, run_policy_issues};

pub use egress::{
    EgressResolver, PinnedEgressPlan, PinnedEgressTarget, SystemEgressResolver,
    plan_egress_allowlist,
};
pub use egress_enforcement::{
    DockerEgressController, NativeLinuxDockerEgressController, PreparedEgressNetwork,
};

pub use sandbox::{
    DEFAULT_BASE_IMAGE, DEFAULT_NAMESPACE, DockerSandbox, NAME, OWNER_LABEL, WORKSPACE_MOUNT,
    container_name,
};
