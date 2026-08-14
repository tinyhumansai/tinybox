//! The model and provider contract behind tinybox.
//!
//! tinybox encapsulates a *box* — an isolated place where code runs — and this
//! crate holds everything that is true regardless of how that isolation is
//! achieved. Backends live in sibling crates and implement the two traits
//! defined here; nothing in this crate knows what Docker or SSH are.
//!
//! # Reach and confinement are separate
//!
//! SSH answers *which machine* a process runs on. Docker answers *what
//! confines it*. tinybox keeps them as independent axes, joined by a
//! [`Placement`]:
//!
//! ```text
//! Host — reach                 Sandbox — confinement
//! ├─ local                     ├─ passthrough
//! └─ ssh                       ├─ docker
//!                              ├─ namespace
//!                              └─ microvm
//! ```
//!
//! Pairing them costs nothing, so `ssh` + `docker` is Docker on a remote
//! machine with no code dedicated to that combination.
//!
//! A box names two placements — [`BoxSpec::runner`] for the agent driving the
//! work and [`BoxSpec::workspace`] for the code itself — because a local runner
//! driving a remote workspace is a case worth expressing.
//!
//! # Backends declare what they do
//!
//! Every [`Sandbox`] returns a [`SandboxCapabilities`] describing its real
//! behavior, and core refuses unsupported requests with [`Error::Unsupported`]
//! instead of degrading silently. A passthrough sandbox that reported the same
//! shape as a microVM would leave callers believing untrusted code had been
//! contained when it had not.
//!
//! # Example
//!
//! ```
//! use tinybox_core::capability::{Capability, IsolationLevel, SandboxCapabilities};
//! use tinybox_core::identity::{HostRef, SandboxRef};
//! use tinybox_core::spec::{BoxSpec, Placement, WorkspaceSource};
//!
//! let placement = Placement::new(HostRef::new("local")?, SandboxRef::new("docker")?);
//! let spec = BoxSpec::new(placement, WorkspaceSource::OciImage("alpine:3".into()))
//!     .with_env("CI", "1");
//!
//! spec.validate()?;
//! assert!(spec.is_colocated());
//!
//! // A backend that cannot fork says so, rather than silently copying.
//! let caps = SandboxCapabilities::PASSTHROUGH;
//! assert_eq!(caps.isolation, IsolationLevel::None);
//! assert!(caps.require("passthrough", Capability::Fork).is_err());
//! # Ok::<(), tinybox_core::Error>(())
//! ```
//!
//! # What ships today
//!
//! [`PassthroughSandbox`] is the only backend in this crate. It runs commands
//! unconfined on whatever [`Host`] it is given, which makes it useful for
//! trusted local work and unsuitable for anything else — and it says so.

pub mod capability;
pub mod clock;
pub mod error;
pub mod identity;
pub mod passthrough;
pub mod runtime;
pub mod spec;
pub mod store;
pub mod template;

pub use capability::{Capability, IsolationLevel, SandboxCapabilities, SnapshotSupport};
pub use clock::{Clock, SystemClock};
pub use error::{Error, Result};
pub use identity::{BoxId, HostRef, SandboxRef, SnapshotId, TemplateName};
pub use passthrough::PassthroughSandbox;
pub use runtime::{BoxInfo, BoxState, ExecOutput, ExecRequest, Host, Sandbox};
pub use spec::{
    BoxSpec, Lifecycle, NetworkPolicy, Placement, PortMapping, Resources, WorkspaceSource,
};
pub use store::{MemoryStore, Store, insert_new};
pub use template::{MemoryTemplates, Templates};
