//! A tinybox sandbox backed by NVIDIA `OpenShell` sandboxes.
//!
//! [OpenShell](https://github.com/NVIDIA/OpenShell) runs each sandbox behind a
//! gateway, as a container, a Kubernetes pod or a microVM, and confines the
//! process inside it with Landlock, seccomp and a default-deny egress proxy.
//! This backend turns tinybox boxes into `OpenShell` sandboxes, so a host can
//! hand untrusted commands to a gateway in a cluster instead of running them on
//! its own machine.
//!
//! # It drives `openshell` through a [`Host`](tinybox_core::Host)
//!
//! Every operation is an `openshell sandbox` command issued through the
//! sandbox's host, never a gRPC client linked into this crate. That is ADR
//! 0004's rule: command construction stays a set of pure functions that can be
//! asserted without a gateway, the dependency graph stays small, and the
//! gateway's address and credentials stay where the `openshell` CLI already
//! keeps them (its gateway configuration), never in tinybox.
//!
//! # What it enforces
//!
//! - **Isolation:** [`IsolationLevel::Kernel`](tinybox_core::IsolationLevel::Kernel).
//!   The gateway's compute driver supplies the outer fence and `OpenShell`'s
//!   in-sandbox runtime adds Landlock and seccomp.
//! - **Network:** only [`NetworkPolicy::Denied`](tinybox_core::NetworkPolicy::Denied).
//!   `OpenShell` denies egress by default; any other policy is refused rather
//!   than approximated, because widening it is a gateway policy decision.
//!   No policy file is passed, so the gateway's default applies; keeping that
//!   default deny-all is the operator's job, as the CLI cannot report it back.
//! - **CPU and memory:** passed as the sandbox's limits.
//! - **Disk:** not per box. Workspace size is the gateway's (or its workload
//!   template's) to set, so `Disk` is declared unsupported.
//!
//! ```no_run
//! use std::sync::Arc;
//! use tinybox_core::{BoxSpec, HostRef, MemoryStore, Placement, Sandbox, SandboxRef, WorkspaceSource};
//! use tinybox_openshell::OpenShellSandbox;
//!
//! # async fn run(host: Arc<dyn tinybox_core::Host>) -> tinybox_core::Result<()> {
//! let sandbox = OpenShellSandbox::new(host, Arc::new(MemoryStore::new()));
//! assert!(sandbox.capabilities().is_suitable_for_untrusted_code());
//!
//! let spec = BoxSpec::new(
//!     Placement::new(HostRef::new("local")?, SandboxRef::new("openshell")?),
//!     WorkspaceSource::OciImage("ghcr.io/example/agent:1".into()),
//! );
//! let info = sandbox.create(&spec).await?;
//! sandbox.destroy(&info.id).await?;
//! # Ok(())
//! # }
//! ```

mod sandbox;

pub use sandbox::{
    BOX_LABEL, DEFAULT_NAMESPACE, NAME, NAMESPACE_LABEL, OpenShellSandbox, sandbox_name,
};
