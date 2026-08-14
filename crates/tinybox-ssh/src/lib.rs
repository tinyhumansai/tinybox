//! A tinybox host that reaches another machine over SSH.
//!
//! [`SshHost`] answers *which machine* a command runs on, and nothing about
//! what confines it. Pairing it with a sandbox is what gives confinement, and
//! because the two are orthogonal (ADR 0002) every existing sandbox works
//! remotely without changes — including Docker, which needed no Docker-side
//! code at all (ADR 0004).
//!
//! ```no_run
//! use std::sync::Arc;
//! use tinybox_core::{Host, MemoryStore, ExecRequest};
//! use tinybox_host::LocalHost;
//! use tinybox_ssh::{SshHost, SshTarget};
//!
//! # async fn run() -> tinybox_core::Result<()> {
//! let remote = Arc::new(SshHost::new(
//!     Arc::new(LocalHost::new()),
//!     SshTarget::new("builder@example.invalid")?,
//! ));
//!
//! let output = remote.run(&ExecRequest::new(["uname", "-s"])).await?;
//! assert_eq!(output.stdout_lossy().trim(), "Linux");
//!
//! // The same sandbox code, now running over there.
//! let sandbox = tinybox_core::PassthroughSandbox::new(remote, Arc::new(MemoryStore::new()));
//! # let _ = sandbox;
//! # Ok(())
//! # }
//! ```
//!
//! # Quoting
//!
//! SSH's exec channel carries a command *string*, not an argument vector, so
//! the vector has to be shell-quoted before it crosses. That is a property of
//! the protocol — an embedded SSH client would face it too — and it is the one
//! place in tinybox where the "no quoting, no injection" guarantee is
//! re-established by hand rather than inherited.

mod host;

pub use host::{NAME, SshHost, SshTarget};
