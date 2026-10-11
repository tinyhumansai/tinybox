//! Hosts that give tinybox reach.
//!
//! A [`Host`](tinybox_core::Host) answers *which machine* a command runs on and
//! normally provides no confinement — that is a
//! [`Sandbox`](tinybox_core::Sandbox)'s job, layered on top. Keeping the two
//! separate is what lets a sandbox compose with any host without either knowing
//! about the other; see [ADR 0002].
//!
//! This crate holds [`LocalHost`], which runs commands on the machine tinybox
//! itself is running on. `SshHost` joins it in M4, at which point every existing
//! sandbox works remotely with no changes.
//!
//! [`JailLocalHost`] is a specialized local provider for a native directory jail.
//! It collects both output streams under one byte budget and owns cancellation,
//! process-group termination, and retained cleanup retries. It requires an
//! available Unix backend and never substitutes an unconfined provider. Callers
//! must inspect the chosen backend's enforcement facts and drain it before
//! releasing the resource; the module adapter owns that lifecycle. Native jail
//! creation is not yet exposed through the module contract.
//!
//! ```no_run
//! use std::sync::Arc;
//! use tinybox_core::{ExecRequest, Host, MemoryStore, PassthroughSandbox, Sandbox};
//! use tinybox_host::LocalHost;
//!
//! # async fn run() -> tinybox_core::Result<()> {
//! let host = Arc::new(LocalHost::new());
//! let output = host.run(&ExecRequest::new(["echo", "hello"])).await?;
//! assert_eq!(output.stdout_lossy().trim(), "hello");
//!
//! // The same host, now behind a sandbox.
//! let sandbox = PassthroughSandbox::new(host, Arc::new(MemoryStore::new()));
//! assert_eq!(sandbox.name(), "passthrough");
//! # Ok(())
//! # }
//! ```
//!
//! [ADR 0002]: https://github.com/tinyhumansai/tinybox/blob/main/docs/adr/0002-host-and-sandbox-are-orthogonal.md
//!
//! [`LOCAL`] is the name `LocalHost` registers under, re-exported so callers
//! can build a [`HostRef`](tinybox_core::HostRef) without hard-coding it.

mod limited;
mod local;

/// Local reach with an enforced combined output budget and supervised cleanup.
pub use limited::{JailLocalHost, LimitedLocalHost, ManagedProcess};

pub use local::{LocalHost, NAME as LOCAL};
