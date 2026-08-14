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

use crate::capability::SandboxCapabilities;
use crate::error::Result;
use crate::identity::{BoxId, SnapshotId};
use crate::spec::BoxSpec;

mod types;

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
}

#[cfg(test)]
mod test;
