//! A sandbox that confines nothing.
//!
//! [`PassthroughSandbox`] runs commands as ordinary processes with the
//! launching user's full privileges. It is the correct choice for trusted local
//! development and the wrong choice for anything else, which is why it declares
//! [`IsolationLevel::None`](crate::IsolationLevel::None) and answers `false` to
//! [`is_suitable_for_untrusted_code`].
//!
//! # Why it lives in core
//!
//! It holds an `Arc<dyn Host>` and delegates every command to it, so it
//! performs no I/O of its own and adds no dependency to this crate. That
//! delegation is also the point: passthrough is generic over reach, so pairing
//! it with an SSH host produces "run it over there, unconfined" without a line
//! of code naming that combination. It is the first working demonstration of
//! the split described in [ADR 0002].
//!
//! # What it will not pretend to do
//!
//! - **Snapshots and forking** are refused, because there is no filesystem
//!   boundary to capture.
//! - **Resource limits** are declared unsupported rather than accepted and
//!   ignored.
//! - **Workspace sources it cannot materialize** — an OCI image, a git URL —
//!   are refused at creation with [`Error::UnsupportedWorkspaceSource`], not
//!   silently reduced to "run in the current directory".
//!
//! [ADR 0002]: https://github.com/tinyhumansai/tinybox/blob/main/docs/adr/0002-host-and-sandbox-are-orthogonal.md
//! [`is_suitable_for_untrusted_code`]: crate::SandboxCapabilities::is_suitable_for_untrusted_code

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;

use crate::capability::{Capability, SandboxCapabilities};
use crate::error::{Error, Result};
use crate::identity::{BoxId, SnapshotId};
use crate::runtime::{BoxInfo, BoxState, ExecOutput, ExecRequest, Host, Sandbox};
use crate::spec::{BoxSpec, WorkspaceSource};
use crate::store::Store;

/// The name this sandbox registers under.
pub const NAME: &str = "passthrough";

/// A sandbox that runs commands directly on its host, unconfined.
#[derive(Debug, Clone)]
pub struct PassthroughSandbox {
    host: Arc<dyn Host>,
    store: Arc<dyn Store>,
}

impl PassthroughSandbox {
    /// Run unconfined commands on `host`, recording boxes in `store`.
    #[must_use]
    pub fn new(host: Arc<dyn Host>, store: Arc<dyn Store>) -> Self {
        Self { host, store }
    }

    /// The directory a box's commands run in.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnsupportedWorkspaceSource`] for every source except
    /// [`WorkspaceSource::LocalDir`]. Materializing an image or a clone needs a
    /// filesystem this sandbox does not own.
    fn workspace_dir(spec: &BoxSpec) -> Result<PathBuf> {
        match &spec.source {
            WorkspaceSource::LocalDir(path) => Ok(path.clone()),
            WorkspaceSource::OciImage(_) => Err(Error::UnsupportedWorkspaceSource {
                sandbox: NAME.to_owned(),
                kind: "OCI image",
            }),
            WorkspaceSource::Snapshot(_) => Err(Error::UnsupportedWorkspaceSource {
                sandbox: NAME.to_owned(),
                kind: "snapshot",
            }),
            WorkspaceSource::GitRepo { .. } => Err(Error::UnsupportedWorkspaceSource {
                sandbox: NAME.to_owned(),
                kind: "git repository",
            }),
        }
    }

    /// Build the command actually handed to the host.
    ///
    /// The box's own environment is applied first and the request's on top, so
    /// a per-command variable wins. The working directory comes from the
    /// request when it names one, and from the workspace otherwise.
    fn resolve(spec: &BoxSpec, request: &ExecRequest) -> Result<ExecRequest> {
        if request.argv.is_empty() {
            return Err(Error::EmptyCommand {
                sandbox: NAME.to_owned(),
            });
        }

        let mut resolved = ExecRequest::new(request.argv.clone());
        resolved.env.clone_from(&spec.env);
        for (key, value) in &request.env {
            resolved.env.insert(key.clone(), value.clone());
        }
        resolved.cwd = match &request.cwd {
            Some(cwd) => Some(cwd.clone()),
            None => Some(Self::workspace_dir(spec)?),
        };
        Ok(resolved)
    }
}

#[async_trait]
impl Sandbox for PassthroughSandbox {
    fn name(&self) -> &'static str {
        NAME
    }

    fn capabilities(&self) -> SandboxCapabilities {
        SandboxCapabilities::PASSTHROUGH
    }

    async fn create(&self, spec: &BoxSpec) -> Result<BoxInfo> {
        spec.validate()?;
        // Fail before recording anything, so a rejected source leaves no box
        // behind for a later command to trip over.
        Self::workspace_dir(spec)?;

        let info = BoxInfo::new(self.store.allocate_id()?, BoxState::Ready, spec.clone());
        self.store.insert(&info)?;
        Ok(info)
    }

    async fn exec(&self, id: &BoxId, request: &ExecRequest) -> Result<ExecOutput> {
        let info = self.store.get(id)?;
        if !info.state.accepts_commands() {
            return Err(Error::InvalidState {
                id: id.as_str().to_owned(),
                actual: info.state,
                expected: BoxState::Ready,
            });
        }

        let resolved = Self::resolve(&info.spec, request)?;
        self.host.run(&resolved).await
    }

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
        self.store.get(id)
    }

    async fn destroy(&self, id: &BoxId) -> Result<()> {
        self.store.remove(id)
    }
}

#[cfg(test)]
mod test;
