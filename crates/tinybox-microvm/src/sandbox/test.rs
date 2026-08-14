//! Tests for the microVM sandbox.
//!
//! A [`ScriptedHost`] stands in for the machine, so everything up to the boot
//! itself is assertable without a hypervisor: what gets staged, what the
//! hypervisor is asked to run, and how the guest's console is read back.
//! `tests/live_microvm.rs` then boots one for real.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use async_trait::async_trait;
use tinybox_core::{
    BoxId, BoxSpec, BoxState, Capability, Error, ExecOutput, ExecRequest, Host, HostRef,
    IsolationLevel, MemoryStore, Placement, Resources, Result, Sandbox, SandboxRef, SnapshotId,
    SnapshotSupport, Store, WorkspaceSource,
};

use tinybox_core::clock::FixedClock;

use super::guest::{BEGIN, EXIT};
use super::{GuestImage, MicroVmSandbox, NAME};

/// A host that answers each command in turn and records what it was asked.
#[derive(Debug, Default)]
struct ScriptedHost {
    seen: Mutex<Vec<ExecRequest>>,
    console: Mutex<String>,
}

impl ScriptedHost {
    /// A host whose guest prints `output` and exits with `status`.
    fn booting(output: &str, status: i32) -> Arc<Self> {
        let host = Self::default();
        *host.console.lock().unwrap_or_else(PoisonError::into_inner) =
            format!("[ 0.00] Linux\r\n{BEGIN}\r\n{output}{EXIT}{status}\r\n[ 0.5] Restarting");
        Arc::new(host)
    }

    fn seen(&self) -> MutexGuard<'_, Vec<ExecRequest>> {
        self.seen.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn commands(&self) -> Vec<Vec<String>> {
        self.seen()
            .iter()
            .map(|request| request.argv.clone())
            .collect()
    }

    /// The command that launched the hypervisor, if one did.
    fn launch(&self) -> Option<Vec<String>> {
        self.commands().into_iter().find(|argv| {
            argv.first()
                .is_some_and(|first| first.contains("firecracker"))
        })
    }
}

#[async_trait]
impl Host for ScriptedHost {
    fn name(&self) -> &'static str {
        "scripted"
    }

    async fn run(&self, request: &ExecRequest) -> Result<ExecOutput> {
        self.seen().push(request.clone());
        let program = request.program().unwrap_or_default();

        let stdout = match program {
            // Staging asks for a directory to write into.
            "mktemp" => "/tmp/tinybox-vm-abc123\n".to_owned(),
            // The workspace listing.
            "find" => "/srv/work/main.rs\n".to_owned(),
            "cat" => "file contents".to_owned(),
            _ if program.contains("firecracker") => self
                .console
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone(),
            _ => String::new(),
        };
        Ok(ExecOutput::new(0, stdout.into_bytes(), Vec::new()))
    }
}

fn image() -> GuestImage {
    GuestImage::with_kernel("/var/lib/tinybox/vmlinux")
        .with_busybox("/usr/bin/busybox")
        .with_firecracker("/usr/local/bin/firecracker")
}

fn sandbox(host: Arc<ScriptedHost>) -> MicroVmSandbox {
    MicroVmSandbox::new(host, Arc::new(MemoryStore::new()), image())
}

fn spec_from(source: WorkspaceSource) -> Result<BoxSpec> {
    Ok(BoxSpec::new(
        Placement::new(HostRef::new("local")?, SandboxRef::new(NAME)?),
        source,
    ))
}

fn spec() -> Result<BoxSpec> {
    spec_from(WorkspaceSource::LocalDir("/srv/work".into()))
}

#[test]
fn it_is_the_only_backend_that_declares_hardware_isolation() {
    let caps = MicroVmSandbox::declared_capabilities();

    assert_eq!(caps.isolation, IsolationLevel::Hardware);
    assert!(caps.is_suitable_for_untrusted_code());
    // The guest is given fixed vCPUs and fixed memory by the hypervisor and
    // cannot see that any more exists, which is a stronger limit than a cgroup.
    assert!(caps.supports(Capability::ResourceLimits));
    // Each command boots a fresh VM, so there is nothing persistent to capture.
    assert_eq!(caps.snapshot, SnapshotSupport::None);
    assert!(!caps.supports(Capability::Fork));
    assert!(!caps.supports(Capability::PortForward));
}

#[tokio::test]
async fn a_command_boots_a_microvm_and_returns_its_output() -> Result<()> {
    let host = ScriptedHost::booting("hello from the guest\r\n", 0);
    let sandbox = sandbox(host.clone());
    let info = sandbox.create(&spec()?).await?;

    let output = sandbox
        .exec(&info.id, &ExecRequest::new(["echo", "hello"]))
        .await?;

    assert_eq!(output.stdout_lossy(), "hello from the guest\n");
    assert_eq!(output.exit_code, 0);
    Ok(())
}

#[tokio::test]
async fn the_hypervisor_is_launched_with_a_configuration_file() -> Result<()> {
    let host = ScriptedHost::booting("", 0);
    let sandbox = sandbox(host.clone());
    let info = sandbox.create(&spec()?).await?;

    sandbox.exec(&info.id, &ExecRequest::new(["true"])).await?;

    let argv = host.launch().unwrap_or_default();
    assert_eq!(argv[0], "/usr/local/bin/firecracker");
    // `--no-api` rather than a socket: a box's VM is configured once and never
    // reconfigured, so a live API would be one more thing to clean up.
    assert!(argv.contains(&"--no-api".to_owned()));
    assert!(argv.contains(&"--config-file".to_owned()));
    Ok(())
}

#[tokio::test]
async fn the_guest_is_staged_before_the_hypervisor_runs() -> Result<()> {
    let host = ScriptedHost::booting("", 0);
    let sandbox = sandbox(host.clone());
    let info = sandbox.create(&spec()?).await?;

    sandbox.exec(&info.id, &ExecRequest::new(["true"])).await?;

    let programs = host
        .commands()
        .into_iter()
        .filter_map(|argv| argv.first().cloned())
        .collect::<Vec<_>>();
    let staged = programs.iter().position(|program| program == "dd");
    let launched = programs
        .iter()
        .position(|program| program.contains("firecracker"));

    // The initramfs has to exist before the hypervisor is told to boot it.
    assert!(staged < launched, "{programs:?}");
    Ok(())
}

#[tokio::test]
async fn the_initramfs_is_written_as_binary_rather_than_through_a_shell() -> Result<()> {
    let host = ScriptedHost::booting("", 0);
    let sandbox = sandbox(host.clone());
    let info = sandbox.create(&spec()?).await?;

    sandbox.exec(&info.id, &ExecRequest::new(["true"])).await?;

    // A cpio archive is binary; a shell redirect would require it to survive
    // being quoted onto a command line.
    let staging = host
        .seen()
        .iter()
        .find(|request| request.program() == Some("dd"))
        .cloned();
    let staging = staging.unwrap_or_else(|| ExecRequest::new(["missing"]));
    assert!(
        staging
            .stdin
            .is_some_and(|bytes| bytes.starts_with(b"070701"))
    );
    Ok(())
}

#[tokio::test]
async fn resources_reach_the_machine_configuration() -> Result<()> {
    let host = ScriptedHost::booting("", 0);
    let sandbox = sandbox(host.clone());
    let spec = spec()?.with_resources(Resources {
        cpu_millis: 1_500,
        memory_bytes: 512 * 1024 * 1024,
        ..Resources::DEFAULT
    });
    let info = sandbox.create(&spec).await?;

    sandbox.exec(&info.id, &ExecRequest::new(["true"])).await?;

    let document = host
        .seen()
        .iter()
        .filter(|request| request.program() == Some("dd"))
        .filter_map(|request| request.stdin.clone())
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .find(|text| text.contains("machine-config"))
        .unwrap_or_default();

    assert!(document.contains("\"vcpu_count\":2"), "{document}");
    assert!(document.contains("\"mem_size_mib\":512"), "{document}");
    // The kernel is referenced where it lives rather than copied per boot.
    assert!(document.contains("/var/lib/tinybox/vmlinux"), "{document}");
    Ok(())
}

#[tokio::test]
async fn a_guest_that_never_started_reports_the_hypervisors_diagnostic() -> Result<()> {
    /// A host whose hypervisor fails before the guest runs.
    #[derive(Debug)]
    struct FailingBoot;

    #[async_trait]
    impl Host for FailingBoot {
        fn name(&self) -> &'static str {
            "failing"
        }

        async fn run(&self, request: &ExecRequest) -> Result<ExecOutput> {
            let program = request.program().unwrap_or_default();
            if program.contains("firecracker") {
                return Ok(ExecOutput::new(
                    1,
                    Vec::new(),
                    b"cannot open /dev/kvm".to_vec(),
                ));
            }
            Ok(ExecOutput::new(
                0,
                if program == "mktemp" {
                    b"/tmp/x\n".to_vec()
                } else {
                    Vec::new()
                },
                Vec::new(),
            ))
        }
    }

    let sandbox = MicroVmSandbox::new(Arc::new(FailingBoot), Arc::new(MemoryStore::new()), image());
    let info = sandbox.create(&spec()?).await?;

    let outcome = sandbox.exec(&info.id, &ExecRequest::new(["true"])).await;

    // The hypervisor's own message is what explains a guest that never ran, and
    // it is far more specific than "the guest never started".
    assert!(
        outcome
            .err()
            .is_some_and(|error| error.to_string().contains("/dev/kvm")),
        "the hypervisor's diagnostic should reach the caller"
    );
    Ok(())
}

#[tokio::test]
async fn sources_it_cannot_build_a_guest_from_are_refused_at_creation() -> Result<()> {
    let host = ScriptedHost::booting("", 0);
    let sandbox = sandbox(host.clone());

    for (source, kind) in [
        (
            WorkspaceSource::OciImage("alpine:3".to_owned()),
            "OCI image",
        ),
        (
            WorkspaceSource::Snapshot(SnapshotId::new("sha-000000000000")?),
            "snapshot",
        ),
        (
            WorkspaceSource::GitRepo {
                url: "https://example.invalid/r.git".to_owned(),
                rev: "main".to_owned(),
            },
            "git repository",
        ),
    ] {
        assert_eq!(
            sandbox.create(&spec_from(source)?).await.err(),
            Some(Error::UnsupportedWorkspaceSource {
                sandbox: NAME.to_owned(),
                kind,
            })
        );
    }
    assert!(host.commands().is_empty());
    Ok(())
}

#[tokio::test]
async fn snapshots_and_forking_are_refused_rather_than_approximated() -> Result<()> {
    let sandbox = sandbox(ScriptedHost::booting("", 0));
    let info = sandbox.create(&spec()?).await?;

    // Firecracker supports both; this backend does not, because a snapshot is
    // only meaningful for a VM that stays running.
    assert_eq!(
        sandbox.snapshot(&info.id).await.err(),
        Some(Error::Unsupported {
            sandbox: NAME.to_owned(),
            capability: Capability::FilesystemSnapshot,
        })
    );
    assert_eq!(
        sandbox
            .fork(&SnapshotId::new("sha-000000000000")?, &spec()?)
            .await
            .err(),
        Some(Error::Unsupported {
            sandbox: NAME.to_owned(),
            capability: Capability::Fork,
        })
    );
    Ok(())
}

#[tokio::test]
async fn a_command_with_no_program_is_refused_before_anything_boots() -> Result<()> {
    let host = ScriptedHost::booting("", 0);
    let sandbox = sandbox(host.clone());
    let info = sandbox.create(&spec()?).await?;

    let empty: Vec<String> = Vec::new();
    assert_eq!(
        sandbox.exec(&info.id, &ExecRequest::new(empty)).await.err(),
        Some(Error::EmptyCommand {
            sandbox: NAME.to_owned()
        })
    );
    assert!(host.launch().is_none());
    Ok(())
}

#[tokio::test]
async fn a_box_can_be_created_inspected_and_destroyed() -> Result<()> {
    let sandbox = sandbox(ScriptedHost::booting("", 0));

    let created = sandbox.create(&spec()?).await?;
    assert_eq!(created.state, BoxState::Ready);
    assert_eq!(sandbox.inspect(&created.id).await?, created);

    sandbox.destroy(&created.id).await?;
    assert!(sandbox.inspect(&created.id).await.is_err());
    Ok(())
}

#[tokio::test]
async fn an_unknown_box_is_reported_without_booting_anything() -> Result<()> {
    let host = ScriptedHost::booting("", 0);
    let sandbox = sandbox(host.clone());
    let missing = BoxId::new("absent")?;
    let expected = Some(Error::UnknownBox {
        id: "absent".to_owned(),
    });

    assert_eq!(sandbox.inspect(&missing).await.err(), expected);
    assert_eq!(sandbox.destroy(&missing).await.err(), expected);
    assert_eq!(
        sandbox
            .exec(&missing, &ExecRequest::new(["true"]))
            .await
            .err(),
        expected
    );
    assert!(host.commands().is_empty());
    Ok(())
}

#[tokio::test]
async fn a_stopped_box_accepts_no_commands() -> Result<()> {
    let host = ScriptedHost::booting("", 0);
    let store = Arc::new(MemoryStore::new());
    let sandbox = MicroVmSandbox::new(host.clone(), store.clone(), image());
    let info = sandbox.create(&spec()?).await?;

    store.set_state(&info.id, BoxState::Stopped)?;

    assert_eq!(
        sandbox
            .exec(&info.id, &ExecRequest::new(["true"]))
            .await
            .err(),
        Some(Error::InvalidState {
            id: info.id.as_str().to_owned(),
            actual: BoxState::Stopped,
            expected: BoxState::Ready,
        })
    );
    assert!(host.launch().is_none());
    Ok(())
}

#[test]
fn a_guest_image_defaults_to_what_is_on_the_path() {
    let image = GuestImage::with_kernel("/k/vmlinux");

    assert_eq!(image.kernel, std::path::Path::new("/k/vmlinux"));
    assert_eq!(image.busybox, std::path::Path::new("/usr/bin/busybox"));
    assert_eq!(image.firecracker, std::path::Path::new("firecracker"));
}

#[tokio::test]
async fn it_is_usable_behind_a_trait_object() -> Result<()> {
    let sandbox: Box<dyn Sandbox> = Box::new(sandbox(ScriptedHost::booting("", 0)));

    assert_eq!(sandbox.name(), "microvm");
    assert_eq!(sandbox.capabilities().isolation, IsolationLevel::Hardware);
    assert_eq!(sandbox.create(&spec()?).await?.state, BoxState::Ready);
    Ok(())
}

/// A host on which one named program fails.
///
/// Staging a guest is half a dozen commands through the host, and each can fail
/// on a real machine — a busybox that is not there, a temporary directory that
/// cannot be made, a disk with nothing left on it. Every one of them has to say
/// which step failed and what the machine said, because "could not boot" sends
/// the reader nowhere.
#[derive(Debug)]
struct BrokenAt {
    /// The program that fails.
    program: &'static str,
    /// What it says on the way out.
    complaint: &'static str,
}

#[async_trait]
impl Host for BrokenAt {
    fn name(&self) -> &'static str {
        "broken"
    }

    async fn run(&self, request: &ExecRequest) -> Result<ExecOutput> {
        let program = request.program().unwrap_or_default();
        if program == self.program {
            return Ok(ExecOutput::new(
                1,
                Vec::new(),
                self.complaint.as_bytes().to_vec(),
            ));
        }
        let stdout = match program {
            "mktemp" => "/tmp/tinybox-vm-abc123\n",
            "find" => "/srv/work/main.rs\n",
            "cat" => "file contents",
            _ => "",
        };
        Ok(ExecOutput::new(0, stdout.as_bytes().to_vec(), Vec::new()))
    }
}

/// Run a command against a host that fails at `program`, and return the error.
async fn failing(program: &'static str, complaint: &'static str) -> Result<String> {
    let host = Arc::new(BrokenAt { program, complaint });
    let sandbox = MicroVmSandbox::new(host, Arc::new(MemoryStore::new()), image());
    let info = sandbox.create(&spec()?).await?;

    let outcome = sandbox.exec(&info.id, &ExecRequest::new(["true"])).await;
    Ok(outcome
        .err()
        .map(|error| error.to_string())
        .unwrap_or_default())
}

#[tokio::test]
async fn a_missing_busybox_names_the_file_it_could_not_read() -> Result<()> {
    // The first thing a boot needs, and the artifact most likely to be absent:
    // nothing installs a static busybox by default.
    let message = failing("cat", "No such file or directory").await?;

    assert!(message.contains("/usr/bin/busybox"), "{message}");
    assert!(message.contains("No such file"), "{message}");
    Ok(())
}

#[tokio::test]
async fn an_unreadable_workspace_is_reported_rather_than_booted_empty() -> Result<()> {
    // Booting with an empty workspace would run the command against nothing and
    // report whatever it made of that, which looks like a broken command rather
    // than a broken box.
    let message = failing("find", "Permission denied").await?;

    assert!(message.contains("Permission denied"), "{message}");
    Ok(())
}

#[tokio::test]
async fn nowhere_to_stage_the_guest_is_reported() -> Result<()> {
    let message = failing("mktemp", "No space left on device").await?;

    assert!(message.contains("No space left"), "{message}");
    Ok(())
}

#[tokio::test]
async fn a_guest_that_cannot_be_written_is_reported_with_its_path() -> Result<()> {
    // `dd` writes both the initramfs and the configuration document, and a
    // short write would produce a machine that fails to boot for reasons the
    // hypervisor cannot explain.
    let message = failing("dd", "Disk quota exceeded").await?;

    assert!(message.contains("Disk quota exceeded"), "{message}");
    assert!(message.contains("/tmp/tinybox-vm-abc123"), "{message}");
    Ok(())
}

#[tokio::test]
async fn a_silent_hypervisor_still_reports_that_the_guest_never_started() -> Result<()> {
    /// A host whose hypervisor exits saying nothing at all.
    #[derive(Debug)]
    struct Silent;

    #[async_trait]
    impl Host for Silent {
        fn name(&self) -> &'static str {
            "silent"
        }

        async fn run(&self, request: &ExecRequest) -> Result<ExecOutput> {
            let stdout = if request.program() == Some("mktemp") {
                "/tmp/x\n"
            } else {
                ""
            };
            Ok(ExecOutput::new(0, stdout.as_bytes().to_vec(), Vec::new()))
        }
    }

    let sandbox = MicroVmSandbox::new(Arc::new(Silent), Arc::new(MemoryStore::new()), image());
    let info = sandbox.create(&spec()?).await?;

    let outcome = sandbox.exec(&info.id, &ExecRequest::new(["true"])).await;

    // With no diagnostic to pass on, the parser's own account is what is left,
    // and it still has to say something a reader can act on.
    let message = outcome
        .err()
        .map(|error| error.to_string())
        .unwrap_or_default();
    assert!(message.contains("failed to boot"), "{message}");
    Ok(())
}

#[tokio::test]
async fn a_box_records_when_it_was_created() -> Result<()> {
    let host = ScriptedHost::booting("", 0);
    let sandbox = sandbox(host).with_clock(Arc::new(FixedClock::at_epoch()));

    let info = sandbox.create(&spec()?).await?;

    // Time comes from the clock so a test never has to wait for one.
    assert_eq!(info.created_at, Some(std::time::UNIX_EPOCH));
    Ok(())
}

#[tokio::test]
async fn the_workspace_root_itself_is_not_written_as_a_file() -> Result<()> {
    /// A host whose `find` names the workspace root as well as a file in it.
    #[derive(Debug)]
    struct ListsTheRoot;

    #[async_trait]
    impl Host for ListsTheRoot {
        fn name(&self) -> &'static str {
            "lists-the-root"
        }

        async fn run(&self, request: &ExecRequest) -> Result<ExecOutput> {
            let program = request.program().unwrap_or_default();
            let stdout = match program {
                "mktemp" => "/tmp/x\n".to_owned(),
                "find" => "/srv/work\n/srv/work/main.rs\n".to_owned(),
                "cat" => "contents".to_owned(),
                _ if program.contains("firecracker") => {
                    format!("{BEGIN}\r\nok\r\n{EXIT}0\r\n")
                }
                _ => String::new(),
            };
            Ok(ExecOutput::new(0, stdout.into_bytes(), Vec::new()))
        }
    }

    let sandbox = MicroVmSandbox::new(
        Arc::new(ListsTheRoot),
        Arc::new(MemoryStore::new()),
        image(),
    );
    let info = sandbox.create(&spec()?).await?;

    // An entry with an empty path would be a cpio record naming nothing, which
    // is not something to hand a kernel.
    let output = sandbox.exec(&info.id, &ExecRequest::new(["true"])).await?;

    assert_eq!(output.exit_code, 0);
    Ok(())
}
