//! A sandbox backed by Firecracker microVMs.

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use tinybox_core::{
    BoxId, BoxInfo, BoxSpec, BoxState, Capability, Clock, Error, ExecOutput, ExecRequest, Host,
    IsolationLevel, Result, Sandbox, SandboxCapabilities, SnapshotId, SnapshotSupport, Store,
    SystemClock, WorkspaceSource,
};

mod config;
mod guest;

pub use guest::WORKSPACE_MOUNT;

/// The name this sandbox registers under.
pub const NAME: &str = "microvm";

/// The artifacts a guest is built from.
///
/// All three have to be supplied: tinybox does not download a kernel, and a
/// backend that silently fetched one would be making a network request nobody
/// asked for at the moment they least expect it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestImage {
    /// An uncompressed Linux kernel, as Firecracker requires.
    pub kernel: PathBuf,
    /// A **statically linked** busybox, which becomes the guest's userland.
    ///
    /// Static because the initramfs carries no libraries; a dynamically linked
    /// one fails to start with an error the guest cannot report.
    pub busybox: PathBuf,
    /// The `firecracker` binary.
    pub firecracker: PathBuf,
}

impl GuestImage {
    /// Use `kernel`, with `busybox` and `firecracker` taken from the `PATH`.
    #[must_use]
    pub fn with_kernel(kernel: impl Into<PathBuf>) -> Self {
        Self {
            kernel: kernel.into(),
            busybox: PathBuf::from("/usr/bin/busybox"),
            firecracker: PathBuf::from("firecracker"),
        }
    }

    /// Use a specific busybox.
    #[must_use]
    pub fn with_busybox(mut self, busybox: impl Into<PathBuf>) -> Self {
        self.busybox = busybox.into();
        self
    }

    /// Use a specific `firecracker` binary.
    #[must_use]
    pub fn with_firecracker(mut self, firecracker: impl Into<PathBuf>) -> Self {
        self.firecracker = firecracker.into();
        self
    }
}

/// A sandbox that runs each command in its own microVM.
///
/// The strongest boundary tinybox offers: the workload gets its own kernel
/// behind a hypervisor, so a kernel exploit that would escape a container has
/// nothing to escape into. It declares
/// [`IsolationLevel::Hardware`](tinybox_core::IsolationLevel::Hardware), and it
/// is the only backend that does.
///
/// # What a box is here
///
/// A record and a set of files, not a running machine. Each command boots a
/// fresh VM — around 800 ms on the machine this was built on — which is what
/// makes the model viable at all: a VM per command would be absurd at
/// container-era boot times and is unremarkable at Firecracker's.
///
/// **Nothing the guest writes comes back.** The whole filesystem is an
/// initramfs in the VM's memory, discarded when it resets. The workspace is
/// copied *in*; changes are not copied out. That is why no snapshot or fork
/// support is declared, and it is the honest shape for the case this backend
/// serves — running code you do not trust and keeping its output.
///
/// # What it needs installed
///
/// `firecracker`, a statically linked `busybox`, an uncompressed guest kernel,
/// and a readable `/dev/kvm`. See [`GuestImage`].
#[derive(Debug, Clone)]
pub struct MicroVmSandbox {
    host: Arc<dyn Host>,
    store: Arc<dyn Store>,
    clock: Arc<dyn Clock>,
    image: GuestImage,
}

impl MicroVmSandbox {
    /// Run microVMs on `host`, recording boxes in `store`.
    #[must_use]
    pub fn new(host: Arc<dyn Host>, store: Arc<dyn Store>, image: GuestImage) -> Self {
        Self {
            host,
            store,
            clock: Arc::new(SystemClock::new()),
            image,
        }
    }

    /// Read creation times from `clock` rather than the operating system.
    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// What this sandbox declares.
    ///
    /// Resource limits are real and enforced by the hypervisor rather than by a
    /// cgroup: the guest is given a fixed number of vCPUs and a fixed amount of
    /// memory, and it has no way to exceed either — it cannot see that any more
    /// exists.
    ///
    /// No snapshots and no forking. Firecracker supports both, and this backend
    /// does not: a snapshot is only meaningful for a VM that stays running, and
    /// each command here boots a fresh one.
    #[must_use]
    pub const fn declared_capabilities() -> SandboxCapabilities {
        SandboxCapabilities::new(IsolationLevel::Hardware, SnapshotSupport::None)
            .with_resource_limits()
    }

    /// The workspace directory a spec names.
    fn workspace(spec: &BoxSpec) -> Result<&std::path::Path> {
        let unsupported = |kind| Error::UnsupportedWorkspaceSource {
            sandbox: NAME.to_owned(),
            kind,
        };
        match &spec.source {
            WorkspaceSource::LocalDir(path) => Ok(path),
            WorkspaceSource::OciImage(_) => Err(unsupported("OCI image")),
            WorkspaceSource::Snapshot(_) => Err(unsupported("snapshot")),
            WorkspaceSource::GitRepo { .. } => Err(unsupported("git repository")),
            _ => Err(unsupported(
                "workspace source this backend does not recognize",
            )),
        }
    }
}

#[async_trait]
impl Sandbox for MicroVmSandbox {
    fn name(&self) -> &'static str {
        NAME
    }

    fn capabilities(&self) -> SandboxCapabilities {
        Self::declared_capabilities()
    }

    async fn create(&self, spec: &BoxSpec) -> Result<BoxInfo> {
        spec.validate()?;
        // Nothing boots here: a box is a record and a directory, and the VM
        // exists only for the length of a command. Checking the source now
        // means an unusable spec fails at `create` rather than at the first
        // `exec`.
        Self::workspace(spec)?;

        tinybox_core::insert_new(self.store.as_ref(), BoxState::Ready, spec, self.clock.now())
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

        let workspace = Self::workspace(&info.spec)?;
        let cmdline = guest::cmdline(request, NAME)?;
        let plan = config::Boot {
            image: &self.image,
            workspace,
            cmdline: &cmdline,
            resources: &info.spec.resources,
        };

        // Firecracker writes the guest's serial console to its own stdout, so
        // the whole run is one command whose output is the guest's.
        let launched = self
            .host
            .run(&plan.command(self.host.as_ref()).await?)
            .await?;
        let console = launched.stdout_lossy();

        let (body, status) = guest::parse_console(&console, NAME).map_err(|error| {
            // Firecracker's own diagnostics land on stderr, and they are what
            // explains a guest that never started.
            if launched.stderr.is_empty() {
                error
            } else {
                Error::Backend {
                    sandbox: NAME.to_owned(),
                    operation: "boot the microVM",
                    message: launched.stderr_lossy().trim().to_owned(),
                }
            }
        })?;

        Ok(ExecOutput::new(status, body.into_bytes(), launched.stderr))
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
