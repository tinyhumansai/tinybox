//! Turning a box into a Firecracker invocation.

use std::path::Path;

use serde::Serialize;
use tinybox_core::{Error, ExecRequest, Host, Resources, Result};

use super::guest::{self, GuestFile};
use super::{GuestImage, NAME};

/// Everything a single boot needs.
#[derive(Debug)]
pub(super) struct Boot<'a> {
    /// Where the kernel, busybox, and hypervisor live.
    pub(super) image: &'a GuestImage,
    /// The directory copied into the guest.
    pub(super) workspace: &'a Path,
    /// The kernel command line, carrying the encoded command.
    pub(super) cmdline: &'a str,
    /// What the guest is allowed.
    pub(super) resources: &'a Resources,
}

/// The Firecracker configuration document.
///
/// Firecracker can be driven either by an HTTP API over a Unix socket or by a
/// configuration file with `--no-api`. The file is used here because a box's VM
/// is configured once and never reconfigured: there is nothing for a live API
/// to do, and a socket would be one more thing to create, clean up, and leak.
#[derive(Debug, Serialize)]
struct Document<'a> {
    #[serde(rename = "boot-source")]
    boot_source: BootSource<'a>,
    #[serde(rename = "machine-config")]
    machine_config: MachineConfig,
    /// No drives at all. The guest's whole filesystem is the initramfs, which
    /// is what removes the need to build, populate, and later read back a disk
    /// image.
    drives: [(); 0],
    /// No network interfaces. This backend offers no egress, so a spec that
    /// asks for one is refused rather than quietly given a machine with no
    /// route out.
    #[serde(rename = "network-interfaces")]
    network_interfaces: [(); 0],
}

#[derive(Debug, Serialize)]
struct BootSource<'a> {
    kernel_image_path: &'a str,
    initrd_path: &'a str,
    boot_args: &'a str,
}

#[derive(Debug, Serialize)]
struct MachineConfig {
    vcpu_count: u8,
    mem_size_mib: u64,
}

/// How many vCPUs a CPU allowance in thousandths becomes.
///
/// Rounded up, and never zero: Firecracker refuses a machine with no CPU, and a
/// caller asking for a tenth of a core wants *some* CPU rather than an error.
/// This is coarser than a cgroup quota — a VM gets whole CPUs — and that
/// coarseness is worth knowing about, so it is stated rather than hidden.
fn vcpus(cpu_millis: u32) -> u8 {
    let whole = cpu_millis.div_ceil(1000).max(1);
    u8::try_from(whole).unwrap_or(u8::MAX)
}

/// How much memory the guest is given.
///
/// Firecracker takes mebibytes, and rounds nothing itself.
fn memory_mib(memory_bytes: u64) -> u64 {
    (memory_bytes / (1024 * 1024)).max(1)
}

impl Boot<'_> {
    /// The command that boots this VM to completion.
    ///
    /// Assembling it needs the workspace read and the initramfs written, both
    /// of which happen through the host — so the same backend works against a
    /// remote machine, exactly as the Docker one does.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] when the workspace or busybox cannot be read, and
    /// [`Error::Backend`] when the guest cannot be staged on the host.
    pub(super) async fn command(&self, host: &dyn Host) -> Result<ExecRequest> {
        let busybox = read(host, &self.image.busybox.display().to_string()).await?;
        let workspace = collect(host, self.workspace).await?;
        let initramfs = guest::initramfs(&busybox, &workspace)?;

        let directory = stage(host, &initramfs).await?;
        let document = self.document(&format!("{directory}/initramfs.cpio"))?;
        write(host, &format!("{directory}/vm.json"), document.as_bytes()).await?;

        Ok(ExecRequest::new([
            self.image.firecracker.display().to_string(),
            "--no-api".to_owned(),
            "--config-file".to_owned(),
            format!("{directory}/vm.json"),
        ]))
    }

    /// The configuration document as JSON.
    ///
    /// The kernel is referenced where it already lives rather than copied into
    /// the staging directory: it is tens of megabytes and identical for every
    /// boot, so copying it per command would dominate the cost of a boot that
    /// otherwise takes under a second.
    fn document(&self, initramfs: &str) -> Result<String> {
        let kernel = self.image.kernel.display().to_string();
        let document = Document {
            boot_source: BootSource {
                kernel_image_path: &kernel,
                initrd_path: initramfs,
                boot_args: self.cmdline,
            },
            machine_config: MachineConfig {
                vcpu_count: vcpus(self.resources.cpu_millis),
                mem_size_mib: memory_mib(self.resources.memory_bytes),
            },
            drives: [],
            network_interfaces: [],
        };

        serde_json::to_string(&document).map_err(|error| Error::Backend {
            sandbox: NAME.to_owned(),
            operation: "describe the microVM",
            message: error.to_string(),
        })
    }
}

/// Read a file through the host.
async fn read(host: &dyn Host, path: &str) -> Result<Vec<u8>> {
    let output = host.run(&ExecRequest::new(["cat", path])).await?;
    if !output.succeeded() {
        return Err(Error::Backend {
            sandbox: NAME.to_owned(),
            operation: "read a guest artifact",
            message: format!("{path}: {}", output.stderr_lossy().trim()),
        });
    }
    Ok(output.stdout)
}

/// Read every file in the workspace through the host.
///
/// One command per file. That is fine locally and would be slow over SSH, where
/// each file costs a round trip; a workspace destined for a microVM is small by
/// nature — it has to fit in the guest's memory — so this has not been worth
/// batching into a single tar stream yet.
async fn collect(host: &dyn Host, workspace: &Path) -> Result<Vec<GuestFile>> {
    let listing = host
        .run(&ExecRequest::new([
            "find",
            &workspace.display().to_string(),
            "-type",
            "f",
        ]))
        .await?;
    if !listing.succeeded() {
        return Err(Error::Backend {
            sandbox: NAME.to_owned(),
            operation: "read the workspace",
            message: listing.stderr_lossy().trim().to_owned(),
        });
    }

    let root = workspace.display().to_string();
    let mut files = Vec::new();
    for path in listing.stdout_lossy().lines() {
        let relative = path
            .strip_prefix(&root)
            .unwrap_or(path)
            .trim_start_matches('/');
        if relative.is_empty() {
            continue;
        }
        files.push(GuestFile {
            path: relative.to_owned(),
            contents: read(host, path).await?,
            executable: false,
        });
    }
    Ok(files)
}

/// Write the initramfs somewhere the hypervisor can read, returning the
/// directory it landed in.
async fn stage(host: &dyn Host, initramfs: &[u8]) -> Result<String> {
    let made = host
        .run(&ExecRequest::new([
            "mktemp",
            "-d",
            "-t",
            "tinybox-vm-XXXXXX",
        ]))
        .await?;
    if !made.succeeded() {
        return Err(Error::Backend {
            sandbox: NAME.to_owned(),
            operation: "stage the microVM",
            message: made.stderr_lossy().trim().to_owned(),
        });
    }
    let directory = made.stdout_lossy().trim().to_owned();

    write(host, &format!("{directory}/initramfs.cpio"), initramfs).await?;
    Ok(directory)
}

/// Write bytes through the host.
async fn write(host: &dyn Host, path: &str, bytes: &[u8]) -> Result<()> {
    // `dd` rather than a shell redirect: the payload is binary and arrives on
    // stdin, so nothing has to survive being quoted into a command line.
    let written = host
        .run(
            &ExecRequest::new(["dd", &format!("of={path}"), "status=none"])
                .with_stdin(bytes.to_vec()),
        )
        .await?;

    if written.succeeded() {
        return Ok(());
    }
    Err(Error::Backend {
        sandbox: NAME.to_owned(),
        operation: "stage the microVM",
        message: format!("{path}: {}", written.stderr_lossy().trim()),
    })
}

#[cfg(test)]
mod test;
