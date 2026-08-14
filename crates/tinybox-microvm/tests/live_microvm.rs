//! Tests that boot real Firecracker microVMs.
//!
//! Gated behind `TINYBOX_LIVE_MICROVM=1` and needing four things on the
//! machine: `firecracker`, a statically linked `busybox`, an uncompressed guest
//! kernel, and a readable `/dev/kvm`. The kernel's location has to be given,
//! because tinybox does not download one:
//!
//! ```sh
//! TINYBOX_LIVE_MICROVM=1 \
//! TINYBOX_MICROVM_KERNEL=~/.local/share/tinybox-microvm/vmlinux \
//! TINYBOX_MICROVM_FIRECRACKER=~/.local/share/tinybox-microvm/firecracker \
//!   cargo test -p tinybox-microvm --test live_microvm
//! ```
//!
//! # What only a real VM can answer
//!
//! Whether the guest boots at all. Everything about the initramfs format, the
//! command encoding, and the console parsing is pinned by unit tests, and all
//! of it can be individually correct while the machine still fails to start —
//! a misaligned cpio entry, a kernel that wants a different console, an `init`
//! that halts instead of resetting. Only a boot proves the pieces fit.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tempfile::TempDir;
use tinybox_core::{
    BoxSpec, Error, ExecRequest, HostRef, MemoryStore, Placement, Resources, Result, Sandbox,
    SandboxRef, WorkspaceSource,
};
use tinybox_host::LocalHost;
use tinybox_microvm::{GuestImage, MicroVmSandbox};

/// Whether the live suite should run, and with which artifacts.
///
/// Returns `None` when the suite is disabled or the kernel was not named, which
/// is the normal case on a machine that has never been set up for this.
fn image() -> Option<GuestImage> {
    std::env::var_os("TINYBOX_LIVE_MICROVM")?;
    let kernel = PathBuf::from(std::env::var_os("TINYBOX_MICROVM_KERNEL")?);

    let mut image = GuestImage::with_kernel(kernel);
    if let Some(firecracker) = std::env::var_os("TINYBOX_MICROVM_FIRECRACKER") {
        image = image.with_firecracker(PathBuf::from(firecracker));
    }
    Some(image)
}

fn sandbox(image: GuestImage) -> MicroVmSandbox {
    MicroVmSandbox::new(
        Arc::new(LocalHost::new()),
        Arc::new(MemoryStore::new()),
        image,
    )
}

fn spec(workspace: &Path) -> Result<BoxSpec> {
    Ok(BoxSpec::new(
        Placement::new(HostRef::new("local")?, SandboxRef::new("microvm")?),
        WorkspaceSource::LocalDir(workspace.into()),
    ))
}

/// A workspace with one file in it.
fn workspace() -> Result<TempDir> {
    let dir = TempDir::new().map_err(|error| Error::io("tempdir", &error))?;
    fs::write(dir.path().join("note.txt"), "workspace file\n")
        .map_err(|error| Error::io("write", &error))?;
    Ok(dir)
}

/// Boot a VM running `script` and return its output.
async fn run(sandbox: &MicroVmSandbox, spec: &BoxSpec, script: &str) -> Result<(String, i32)> {
    let info = sandbox.create(spec).await?;
    let output = sandbox
        .exec(
            &info.id,
            &ExecRequest::new(["/bin/busybox", "sh", "-c", script]),
        )
        .await?;
    sandbox.destroy(&info.id).await?;
    Ok((output.stdout_lossy().trim().to_owned(), output.exit_code))
}

#[tokio::test]
async fn live_a_microvm_boots_and_runs_a_command() -> Result<()> {
    let Some(image) = image() else { return Ok(()) };
    let dir = workspace()?;

    let (out, status) = run(
        &sandbox(image),
        &spec(dir.path())?,
        "echo hello from the guest",
    )
    .await?;

    assert_eq!(out, "hello from the guest");
    assert_eq!(status, 0);
    Ok(())
}

#[tokio::test]
async fn live_the_guest_has_its_own_kernel() -> Result<()> {
    let Some(image) = image() else { return Ok(()) };
    let dir = workspace()?;

    let (guest, _) = run(&sandbox(image), &spec(dir.path())?, "uname -r").await?;
    let host = String::from_utf8_lossy(
        &std::process::Command::new("uname")
            .arg("-r")
            .output()
            .map_err(|error| Error::io("uname", &error))?
            .stdout,
    )
    .trim()
    .to_owned();

    // The whole point of this backend: not a namespace of the host kernel, a
    // different kernel entirely. A container cannot produce this result.
    assert_ne!(guest, host, "the guest is running the host's kernel");
    assert!(!guest.is_empty());
    Ok(())
}

#[tokio::test]
async fn live_the_workspace_is_visible_inside_the_guest() -> Result<()> {
    let Some(image) = image() else { return Ok(()) };
    let dir = workspace()?;

    let (out, _) = run(
        &sandbox(image),
        &spec(dir.path())?,
        "cat /workspace/note.txt",
    )
    .await?;

    assert_eq!(out, "workspace file");
    Ok(())
}

#[tokio::test]
async fn live_nested_workspace_files_arrive_intact() -> Result<()> {
    let Some(image) = image() else { return Ok(()) };
    let dir = workspace()?;
    fs::create_dir_all(dir.path().join("src/deep")).map_err(|error| Error::io("mkdir", &error))?;
    fs::write(dir.path().join("src/deep/mod.rs"), "nested content")
        .map_err(|error| Error::io("write", &error))?;

    // A cpio entry whose parent directory was not written first is silently
    // dropped by the kernel, which is exactly the failure a unit test cannot
    // see.
    let (out, _) = run(
        &sandbox(image),
        &spec(dir.path())?,
        "cat /workspace/src/deep/mod.rs",
    )
    .await?;

    assert_eq!(out, "nested content");
    Ok(())
}

#[tokio::test]
async fn live_nothing_the_guest_writes_comes_back() -> Result<()> {
    let Some(image) = image() else { return Ok(()) };
    let dir = workspace()?;
    let sandbox = sandbox(image);

    let (out, _) = run(
        &sandbox,
        &spec(dir.path())?,
        "echo changed > /workspace/note.txt; cat /workspace/note.txt",
    )
    .await?;

    // Inside the VM the write succeeds — the initramfs is writable memory...
    assert_eq!(out, "changed");
    // ...and the host's copy is untouched, because the guest's whole filesystem
    // is discarded when the machine resets. This is the documented limit of the
    // backend, asserted rather than left implied.
    assert_eq!(
        fs::read_to_string(dir.path().join("note.txt"))
            .map_err(|error| Error::io("read", &error))?,
        "workspace file\n"
    );
    Ok(())
}

#[tokio::test]
async fn live_a_failing_command_reports_its_status() -> Result<()> {
    let Some(image) = image() else { return Ok(()) };
    let dir = workspace()?;

    let (_, status) = run(&sandbox(image), &spec(dir.path())?, "exit 7").await?;

    assert_eq!(status, 7);
    Ok(())
}

#[tokio::test]
async fn live_kernel_messages_do_not_reach_the_caller() -> Result<()> {
    let Some(image) = image() else { return Ok(()) };
    let dir = workspace()?;

    let (out, _) = run(&sandbox(image), &spec(dir.path())?, "echo only-this").await?;

    // The serial console carries the whole boot, and the caller must get the
    // command's output rather than a kernel log with their line buried in it.
    assert_eq!(out, "only-this");
    assert!(!out.contains("Linux version"));
    assert!(!out.contains("Restarting"));
    Ok(())
}

#[tokio::test]
async fn live_the_guest_gets_the_memory_it_was_given_and_no_more() -> Result<()> {
    let Some(image) = image() else { return Ok(()) };
    let dir = workspace()?;
    let spec = spec(dir.path())?.with_resources(Resources {
        memory_bytes: 256 * 1024 * 1024,
        ..Resources::DEFAULT
    });

    let (out, _) = run(
        &sandbox(image),
        &spec,
        "grep MemTotal /proc/meminfo | tr -s ' ' | cut -d' ' -f2",
    )
    .await?;

    // A hypervisor limit is stronger than a cgroup one: the guest cannot see
    // that more memory exists anywhere, so there is nothing to exceed. The
    // kernel reserves some of what it is given, so this checks a range.
    let total_kib: u64 = out.trim().parse().unwrap_or(0);
    assert!(
        (150_000..=262_144).contains(&total_kib),
        "expected roughly 256 MiB, saw {total_kib} KiB"
    );
    Ok(())
}

#[tokio::test]
async fn live_the_guest_gets_the_cpus_it_was_given() -> Result<()> {
    let Some(image) = image() else { return Ok(()) };
    let dir = workspace()?;
    let spec = spec(dir.path())?.with_resources(Resources {
        cpu_millis: 1_000,
        ..Resources::DEFAULT
    });

    let (out, _) = run(&sandbox(image), &spec, "nproc").await?;

    // The host has many more; the guest is built with one.
    assert_eq!(out, "1");
    Ok(())
}

#[tokio::test]
async fn live_the_guest_cannot_see_the_host_filesystem() -> Result<()> {
    let Some(image) = image() else { return Ok(()) };
    let dir = workspace()?;

    let (out, _) = run(
        &sandbox(image),
        &spec(dir.path())?,
        "test -e /home && echo LEAKED || echo absent; \
         test -e /etc/passwd && echo ETC || echo no-etc",
    )
    .await?;

    // There is no bind mount to get wrong here — the guest's filesystem is one
    // this process constructed, and the host's is not reachable from inside a
    // different machine.
    assert!(out.contains("absent"), "{out}");
    assert!(out.contains("no-etc"), "{out}");
    Ok(())
}

#[tokio::test]
async fn live_the_guest_has_no_network() -> Result<()> {
    let Some(image) = image() else { return Ok(()) };
    let dir = workspace()?;

    let (out, _) = run(
        &sandbox(image),
        &spec(dir.path())?,
        "ip -o link 2>/dev/null | wc -l",
    )
    .await?;

    // No interfaces are configured, so the machine has loopback at most.
    let interfaces: usize = out.trim().parse().unwrap_or(usize::MAX);
    assert!(
        interfaces <= 1,
        "expected no network, saw {interfaces} interfaces"
    );
    Ok(())
}

#[tokio::test]
async fn live_an_argument_is_never_interpreted_by_the_guest_shell() -> Result<()> {
    let Some(image) = image() else { return Ok(()) };
    let dir = workspace()?;
    let sandbox = sandbox(image);
    let info = sandbox.create(&spec(dir.path())?).await?;

    let output = sandbox
        .exec(
            &info.id,
            &ExecRequest::new(["/bin/busybox", "echo", "; touch /workspace/PWNED"]),
        )
        .await?;

    sandbox.destroy(&info.id).await?;
    // The command becomes text on a kernel command line and then a shell script
    // again, so it needs the same quoting SSH does.
    assert_eq!(output.stdout_lossy().trim(), "; touch /workspace/PWNED");
    Ok(())
}

#[tokio::test]
async fn live_the_environment_and_directory_apply_inside_the_guest() -> Result<()> {
    let Some(image) = image() else { return Ok(()) };
    let dir = workspace()?;
    fs::create_dir_all(dir.path().join("sub")).map_err(|error| Error::io("mkdir", &error))?;
    fs::write(dir.path().join("sub/marker"), "here").map_err(|error| Error::io("write", &error))?;

    let sandbox = sandbox(image);
    let info = sandbox.create(&spec(dir.path())?).await?;
    let output = sandbox
        .exec(
            &info.id,
            &ExecRequest::new([
                "/bin/busybox",
                "sh",
                "-c",
                "pwd; cat marker; echo $GREETING",
            ])
            .with_cwd("/workspace/sub")
            .with_env("GREETING", "hello there"),
        )
        .await?;

    sandbox.destroy(&info.id).await?;
    let seen = output.stdout_lossy();
    // A kernel command line has no notion of either, so both become shell
    // inside the guest.
    assert!(seen.contains("/workspace/sub"), "{seen}");
    assert!(seen.contains("here"), "{seen}");
    assert!(seen.contains("hello there"), "{seen}");
    Ok(())
}
