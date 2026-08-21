//! The two provider traits every backend implements.
//!
//! [`Host`] answers *which machine* — it can run a command and move bytes
//! somewhere. [`Sandbox`] answers *what confines it* — it owns box lifecycle,
//! isolation, and snapshots. Backends implement one or the other, never both,
//! which is what lets `ssh` and `docker` compose without either knowing about
//! the other.
//!
//! Both traits are object-safe and used as `Arc<dyn _>` in a provider registry,
//! which is why they carry `async_trait` rather than native `async fn`. Both
//! also require `Debug`, because the types holding them derive it and
//! `missing_debug_implementations` is denied workspace-wide.
//!
//! # Implementing a sandbox honestly
//!
//! [`Sandbox::capabilities`] must describe what the backend really does. Core
//! checks the declaration before dispatching and surfaces
//! [`Error::Unsupported`](crate::error::Error::Unsupported), so a backend should
//! return an accurate [`SandboxCapabilities`] and let the check fail rather
//! than emulate something it cannot deliver.

use async_trait::async_trait;

use std::net::SocketAddr;

use crate::capability::{Capability, SandboxCapabilities};
use crate::error::{Error, Result};
use crate::identity::{BoxId, ProcessId, SnapshotId};
use crate::spec::BoxSpec;

mod forward;
#[cfg(test)]
mod forward_test;
mod types;

pub use forward::{Forward, ForwardGuard};
pub use types::{BoxInfo, BoxState, ExecOutput, ExecRequest};

/// A machine tinybox can reach and run commands on.
///
/// A host provides no confinement of its own. `local` runs a child process;
/// `ssh` opens a channel to another machine. Confinement is the [`Sandbox`]'s
/// job, layered on top.
#[async_trait]
pub trait Host: std::fmt::Debug + Send + Sync + 'static {
    /// The name this host is registered under, matching
    /// [`HostRef`](crate::identity::HostRef).
    fn name(&self) -> &str;

    /// Run a command to completion and collect its output.
    ///
    /// # Errors
    ///
    /// Returns an error when the command cannot be started, the connection to
    /// the machine fails, or the host is otherwise unreachable. A command that
    /// runs and exits non-zero is a success here: the status is reported in
    /// [`ExecOutput::exit_code`], because a failing command is a result, not a
    /// transport fault.
    async fn run(&self, request: &ExecRequest) -> Result<ExecOutput>;

    /// Make `remote` — an address in *this host's* address space — reachable
    /// from the machine tinybox is running on.
    ///
    /// A sandbox publishing a guest port
    /// ([`PortMapping`](crate::spec::PortMapping)) puts it on its host. When
    /// that host is another machine, the caller still cannot connect, and no
    /// sandbox-side configuration fixes it — closing that gap is a question
    /// about reach, which is this trait's subject. A local host answers by
    /// handing the address straight back.
    ///
    /// The returned [`Forward`] is a guard: the path lasts exactly as long as
    /// it is held.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Unsupported`] by default, so a host that cannot tunnel
    /// says so rather than returning an address nothing is listening on. Also
    /// returns an error when the tunnel cannot be established.
    async fn forward(&self, remote: SocketAddr) -> Result<Forward> {
        let _ = remote;
        Err(Error::Unsupported {
            sandbox: self.name().to_owned(),
            capability: Capability::PortForward,
        })
    }
}

/// A confinement that boxes are created inside.
///
/// Implementations range from [`SandboxCapabilities::PASSTHROUGH`], which wraps
/// nothing at all, to a hypervisor-backed sandbox with its own kernel.
#[async_trait]
pub trait Sandbox: std::fmt::Debug + Send + Sync + 'static {
    /// The name this sandbox is registered under, matching
    /// [`SandboxRef`](crate::identity::SandboxRef).
    fn name(&self) -> &str;

    /// What this sandbox can actually do.
    ///
    /// Callers use this to choose a backend, and core uses it to reject
    /// unsupported requests before they reach the implementation.
    fn capabilities(&self) -> SandboxCapabilities;

    /// Create a box from `spec` without starting any workload in it.
    ///
    /// # Errors
    ///
    /// Returns an error when the spec is invalid, the workspace source cannot
    /// be materialized, or the backend cannot allocate the requested resources.
    async fn create(&self, spec: &BoxSpec) -> Result<BoxInfo>;

    /// Run a command inside an existing box.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnknownBox`](crate::error::Error::UnknownBox) when `id` does
    /// not resolve, [`Error::InvalidState`](crate::error::Error::InvalidState) when
    /// the box is not running, or a backend error when the command cannot be
    /// started.
    async fn exec(&self, id: &BoxId, request: &ExecRequest) -> Result<ExecOutput>;

    /// Capture the current state of a box.
    ///
    /// What a snapshot contains depends on
    /// [`SandboxCapabilities::snapshot`]; a container sandbox captures the
    /// filesystem alone, while a microVM sandbox also captures live memory.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Unsupported`](crate::error::Error::Unsupported) when this
    /// sandbox does not snapshot, or
    /// [`Error::UnknownBox`](crate::error::Error::UnknownBox) when `id` does not
    /// resolve.
    async fn snapshot(&self, id: &BoxId) -> Result<SnapshotId>;

    /// Branch a snapshot into a new independent box.
    ///
    /// This is how both templates and resume work: a template is a named
    /// snapshot, and resuming a stopped box forks its newest one.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Unsupported`](crate::error::Error::Unsupported) when this
    /// sandbox cannot fork, or
    /// [`Error::UnknownSnapshot`](crate::error::Error::UnknownSnapshot) when
    /// `snapshot` does not resolve.
    async fn fork(&self, snapshot: &SnapshotId, spec: &BoxSpec) -> Result<BoxInfo>;

    /// Describe a box without changing it.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnknownBox`](crate::error::Error::UnknownBox) when `id` does
    /// not resolve.
    async fn inspect(&self, id: &BoxId) -> Result<BoxInfo>;

    /// Destroy a box and release everything it holds.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnknownBox`](crate::error::Error::UnknownBox) when `id` does
    /// not resolve.
    async fn destroy(&self, id: &BoxId) -> Result<()>;

    /// Start a command in a box and leave it running.
    ///
    /// Where [`Sandbox::exec`] waits, this returns as soon as the process is
    /// started, handing back an identifier for asking about it later. It is how
    /// a server gets into a box; `exec` would never return.
    ///
    /// See [`detach`](crate::detach) for the mechanism, and for what a backend
    /// is promising by declaring
    /// [`Capability::Detach`](crate::capability::Capability::Detach).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Unsupported`] by default. A sandbox that cannot host a
    /// process between commands must leave it that way: a background process
    /// that cannot be found or stopped is worse than a refusal, because it
    /// looks like it worked.
    async fn spawn(&self, id: &BoxId, request: &ExecRequest) -> Result<ProcessId> {
        let (_, _) = (id, request);
        Err(Error::Unsupported {
            sandbox: self.name().to_owned(),
            capability: Capability::Detach,
        })
    }

    /// Whether a process started by [`Sandbox::spawn`] is still running.
    ///
    /// A process that has finished is `false`, not an error: "it exited" is an
    /// answer, and conflating it with an unreachable box would hide a real
    /// failure behind an ordinary one.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Unsupported`] by default, and a backend error when the
    /// box cannot be reached to ask.
    async fn is_running(&self, id: &BoxId, process: &ProcessId) -> Result<bool> {
        let (_, _) = (id, process);
        Err(Error::Unsupported {
            sandbox: self.name().to_owned(),
            capability: Capability::Detach,
        })
    }

    /// Stop a process started by [`Sandbox::spawn`].
    ///
    /// Succeeds when the process was already gone: stopping something that has
    /// already stopped is the outcome the caller wanted.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Unsupported`] by default, and a backend error when the
    /// box cannot be reached.
    async fn stop(&self, id: &BoxId, process: &ProcessId) -> Result<()> {
        let (_, _) = (id, process);
        Err(Error::Unsupported {
            sandbox: self.name().to_owned(),
            capability: Capability::Detach,
        })
    }
}

#[cfg(test)]
mod test;
