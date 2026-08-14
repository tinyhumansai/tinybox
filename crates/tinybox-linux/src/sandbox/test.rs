//! Tests for the namespace sandbox.
//!
//! What a sandbox binds, unshares, and limits *is* the security boundary, so
//! these assert on the exact `bwrap` command line. `tests/live_namespaces.rs`
//! then confirms the boundary actually holds against a real kernel — this file
//! pins the intent, that one pins the reality.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use async_trait::async_trait;
use tinybox_core::{
    BoxId, BoxSpec, BoxState, Capability, Error, ExecOutput, ExecRequest, Host, HostRef,
    IsolationLevel, MemoryStore, NetworkPolicy, Placement, Resources, Result, Sandbox, SandboxRef,
    SnapshotId, SnapshotSupport, Store, WorkspaceSource,
};

use super::{NAME, NamespaceSandbox, args};

/// A host that records what it was asked to run.
#[derive(Debug, Default)]
struct RecordingHost {
    seen: Mutex<Vec<Vec<String>>>,
}

impl RecordingHost {
    fn seen(&self) -> MutexGuard<'_, Vec<Vec<String>>> {
        self.seen.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn last(&self) -> Vec<String> {
        self.seen().last().cloned().unwrap_or_default()
    }

    fn ran_anything(&self) -> bool {
        !self.seen().is_empty()
    }
}

#[async_trait]
impl Host for RecordingHost {
    fn name(&self) -> &'static str {
        "recording"
    }

    async fn run(&self, request: &ExecRequest) -> Result<ExecOutput> {
        self.seen().push(request.argv.clone());
        Ok(ExecOutput::new(0, b"ran".to_vec(), Vec::new()))
    }
}

fn sandbox() -> (NamespaceSandbox, Arc<RecordingHost>) {
    let host = Arc::new(RecordingHost::default());
    (
        NamespaceSandbox::new(host.clone(), Arc::new(MemoryStore::new())),
        host,
    )
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

/// Whether `argv` contains `flag` as its own word.
fn has(argv: &[String], flag: &str) -> bool {
    argv.iter().any(|part| part == flag)
}

/// The value following `flag`.
fn value_of<'a>(argv: &'a [String], flag: &str) -> Option<&'a str> {
    argv.iter()
        .position(|part| part == flag)
        .and_then(|index| argv.get(index + 1))
        .map(String::as_str)
}

#[test]
fn it_declares_kernel_isolation_and_nothing_it_cannot_do() {
    let caps = NamespaceSandbox::declared_capabilities(false);

    assert_eq!(caps.isolation, IsolationLevel::Kernel);
    assert!(caps.is_suitable_for_untrusted_code());
    // Each command is a fresh sandbox, so there is no persistent filesystem to
    // capture and nothing to fork from.
    assert_eq!(caps.snapshot, SnapshotSupport::None);
    assert!(!caps.supports(Capability::Fork));
    assert!(!caps.supports(Capability::PortForward));
    assert!(!caps.supports(Capability::PauseResume));
    // Limits need a systemd user session, so they are not claimed by default.
    assert!(!caps.supports(Capability::ResourceLimits));
    assert!(caps.declared().is_empty());
}

#[test]
fn limits_are_declared_only_when_asked_for() {
    let caps = NamespaceSandbox::declared_capabilities(true);

    assert!(caps.supports(Capability::ResourceLimits));
    assert_eq!(caps.declared(), [Capability::ResourceLimits]);
}

#[tokio::test]
async fn every_isolating_namespace_is_unshared() -> Result<()> {
    let (sandbox, host) = sandbox();
    let info = sandbox.create(&spec()?).await?;

    sandbox.exec(&info.id, &ExecRequest::new(["true"])).await?;

    let argv = host.last();
    assert_eq!(argv.first().map(String::as_str), Some("bwrap"));
    // Each of these is part of the boundary; losing one silently would leave a
    // sandbox that looks isolated and is not.
    for flag in [
        "--unshare-user",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--unshare-cgroup",
    ] {
        assert!(has(&argv, flag), "{flag} missing from {argv:?}");
    }
    Ok(())
}

#[tokio::test]
async fn the_network_namespace_is_unshared_unless_egress_is_allowed() -> Result<()> {
    let (sandbox, host) = sandbox();
    let denied = sandbox.create(&spec()?).await?;

    sandbox
        .exec(&denied.id, &ExecRequest::new(["true"]))
        .await?;
    assert!(has(&host.last(), "--unshare-net"));

    let open = sandbox
        .create(&spec()?.with_network(NetworkPolicy::Egress))
        .await?;
    sandbox.exec(&open.id, &ExecRequest::new(["true"])).await?;
    assert!(!has(&host.last(), "--unshare-net"));
    Ok(())
}

#[tokio::test]
async fn the_sandbox_dies_with_tinybox_and_gets_its_own_session() -> Result<()> {
    let (sandbox, host) = sandbox();
    let info = sandbox.create(&spec()?).await?;

    sandbox.exec(&info.id, &ExecRequest::new(["true"])).await?;

    let argv = host.last();
    // Without this a sandbox outlives the box it belongs to, reparented to init.
    assert!(has(&argv, "--die-with-parent"));
    // Without this the sandboxed process can inject keystrokes into the
    // caller's terminal through TIOCSTI.
    assert!(has(&argv, "--new-session"));
    Ok(())
}

#[tokio::test]
async fn the_system_is_mounted_read_only_and_nothing_else_is() -> Result<()> {
    let (sandbox, host) = sandbox();
    let info = sandbox.create(&spec()?).await?;

    sandbox.exec(&info.id, &ExecRequest::new(["true"])).await?;

    let argv = host.last();
    // `/usr` read-only and no writable bind of anything outside the workspace.
    assert_eq!(value_of(&argv, "--ro-bind"), Some("/usr"));
    let writable = argv
        .iter()
        .enumerate()
        .filter(|(_, part)| part.as_str() == "--bind")
        .filter_map(|(index, _)| argv.get(index + 1).cloned())
        .collect::<Vec<_>>();
    assert_eq!(
        writable,
        ["/srv/work"],
        "only the workspace may be writable"
    );
    Ok(())
}

#[tokio::test]
async fn the_host_configuration_directory_is_not_handed_over_wholesale() -> Result<()> {
    let (sandbox, host) = sandbox();
    let info = sandbox.create(&spec()?).await?;

    sandbox.exec(&info.id, &ExecRequest::new(["true"])).await?;

    let argv = host.last();
    // Binding all of `/etc` would hand the box every credential and host key
    // the user can read. Only what a normal command needs is bound.
    let bound_etc = argv
        .iter()
        .filter(|part| part.starts_with("/etc"))
        .cloned()
        .collect::<Vec<_>>();
    assert!(!bound_etc.contains(&"/etc".to_owned()), "{bound_etc:?}");
    assert!(bound_etc.contains(&"/etc/passwd".to_owned()));
    assert!(bound_etc.contains(&"/etc/ssl/certs".to_owned()));
    // Missing files must not be fatal on an unusual machine.
    assert!(has(&argv, "--ro-bind-try"));
    Ok(())
}

#[tokio::test]
async fn the_workspace_is_bound_and_becomes_the_working_directory() -> Result<()> {
    let (sandbox, host) = sandbox();
    let info = sandbox.create(&spec()?).await?;

    sandbox.exec(&info.id, &ExecRequest::new(["ls"])).await?;

    let argv = host.last();
    assert_eq!(value_of(&argv, "--bind"), Some("/srv/work"));
    assert_eq!(value_of(&argv, "--chdir"), Some("/workspace"));
    Ok(())
}

#[tokio::test]
async fn an_explicit_working_directory_overrides_the_workspace() -> Result<()> {
    let (sandbox, host) = sandbox();
    let info = sandbox.create(&spec()?).await?;

    sandbox
        .exec(&info.id, &ExecRequest::new(["pwd"]).with_cwd("/tmp"))
        .await?;

    assert_eq!(value_of(&host.last(), "--chdir"), Some("/tmp"));
    Ok(())
}

#[tokio::test]
async fn the_environment_is_cleared_and_then_rebuilt() -> Result<()> {
    let (sandbox, host) = sandbox();
    let spec = spec()?.with_env("FROM_BOX", "1");
    let info = sandbox.create(&spec).await?;

    sandbox
        .exec(
            &info.id,
            &ExecRequest::new(["env"]).with_env("FROM_COMMAND", "2"),
        )
        .await?;

    let argv = host.last();
    // The caller's own environment must not leak in: it routinely holds tokens.
    assert!(has(&argv, "--clearenv"));
    let set = argv
        .iter()
        .enumerate()
        .filter(|(_, part)| part.as_str() == "--setenv")
        .filter_map(|(index, _)| argv.get(index + 1).cloned())
        .collect::<Vec<_>>();
    assert_eq!(set, ["FROM_BOX", "FROM_COMMAND"]);
    Ok(())
}

#[tokio::test]
async fn the_command_is_separated_from_bwraps_own_options() -> Result<()> {
    let (sandbox, host) = sandbox();
    let info = sandbox.create(&spec()?).await?;

    sandbox
        .exec(&info.id, &ExecRequest::new(["-weird-program", "-x"]))
        .await?;

    let argv = host.last();
    let separator = argv.iter().position(|part| part == "--");
    // Everything after `--` is the command, so an argument starting with a dash
    // cannot be read as a bwrap flag.
    assert_eq!(
        separator.map(|index| &argv[index + 1..]),
        Some(&["-weird-program".to_owned(), "-x".to_owned()][..])
    );
    Ok(())
}

#[tokio::test]
async fn limits_wrap_the_sandbox_in_a_systemd_scope() -> Result<()> {
    let host = Arc::new(RecordingHost::default());
    let sandbox =
        NamespaceSandbox::new(host.clone(), Arc::new(MemoryStore::new())).with_cgroup_limits();
    let spec = spec()?.with_resources(Resources {
        cpu_millis: 1_500,
        memory_bytes: 512 * 1024 * 1024,
        pids_max: 64,
        disk_bytes: 1024 * 1024 * 1024,
    });
    let info = sandbox.create(&spec).await?;

    sandbox.exec(&info.id, &ExecRequest::new(["true"])).await?;

    let argv = host.last();
    assert_eq!(argv.first().map(String::as_str), Some("systemd-run"));
    assert!(has(&argv, "--user"));
    assert!(has(&argv, "--scope"));
    let properties = argv
        .iter()
        .enumerate()
        .filter(|(_, part)| part.as_str() == "--property")
        .filter_map(|(index, _)| argv.get(index + 1).cloned())
        .collect::<Vec<_>>();
    // systemd takes CPU as a percentage where 100% is one core.
    // `MemorySwapMax=0` is not decoration: without it the memory cap is
    // advisory on any machine with swap, and a box asked for 512 MiB will
    // quietly use far more.
    assert_eq!(
        properties,
        [
            "MemoryMax=536870912",
            "MemorySwapMax=0",
            "CPUQuota=150%",
            "TasksMax=64",
        ]
    );
    // The sandbox still runs inside the scope.
    assert!(has(&argv, "bwrap"));
    Ok(())
}

#[tokio::test]
async fn without_limits_there_is_no_scope_at_all() -> Result<()> {
    let (sandbox, host) = sandbox();
    let info = sandbox.create(&spec()?).await?;

    sandbox.exec(&info.id, &ExecRequest::new(["true"])).await?;

    // Declaring no limits and then quietly running under someone else's cgroup
    // would be the same dishonesty from the other direction.
    assert!(!has(&host.last(), "systemd-run"));
    Ok(())
}

#[tokio::test]
async fn sources_it_cannot_bind_are_refused_at_creation() -> Result<()> {
    let (sandbox, host) = sandbox();

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
                url: "https://example.invalid/repo.git".to_owned(),
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
    assert!(!host.ran_anything());
    Ok(())
}

#[tokio::test]
async fn snapshots_and_forking_are_refused_rather_than_approximated() -> Result<()> {
    let (sandbox, _host) = sandbox();
    let info = sandbox.create(&spec()?).await?;

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
async fn a_command_with_no_program_is_refused() -> Result<()> {
    let (sandbox, host) = sandbox();
    let info = sandbox.create(&spec()?).await?;

    let empty: Vec<String> = Vec::new();
    assert_eq!(
        sandbox.exec(&info.id, &ExecRequest::new(empty)).await.err(),
        Some(Error::EmptyCommand {
            sandbox: NAME.to_owned()
        })
    );
    assert!(!host.ran_anything());
    Ok(())
}

#[tokio::test]
async fn a_box_can_be_created_inspected_and_destroyed() -> Result<()> {
    let (sandbox, _host) = sandbox();

    let created = sandbox.create(&spec()?).await?;
    assert_eq!(created.state, BoxState::Ready);
    assert_eq!(sandbox.inspect(&created.id).await?, created);

    sandbox.destroy(&created.id).await?;
    assert!(sandbox.inspect(&created.id).await.is_err());
    Ok(())
}

#[tokio::test]
async fn a_stopped_box_accepts_no_commands() -> Result<()> {
    let host = Arc::new(RecordingHost::default());
    let store = Arc::new(MemoryStore::new());
    let sandbox = NamespaceSandbox::new(host.clone(), store.clone());
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
    assert!(!host.ran_anything());
    Ok(())
}

#[tokio::test]
async fn an_unknown_box_is_reported_without_running_anything() -> Result<()> {
    let (sandbox, host) = sandbox();
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
    assert!(!host.ran_anything());
    Ok(())
}

#[tokio::test]
async fn it_is_usable_behind_a_trait_object() -> Result<()> {
    let sandbox: Box<dyn Sandbox> = Box::new(NamespaceSandbox::new(
        Arc::new(RecordingHost::default()),
        Arc::new(MemoryStore::new()),
    ));

    assert_eq!(sandbox.name(), "namespace");
    assert!(sandbox.capabilities().is_suitable_for_untrusted_code());
    assert_eq!(sandbox.create(&spec()?).await?.state, BoxState::Ready);
    Ok(())
}

#[test]
fn the_workspace_mount_point_is_stable() -> Result<()> {
    // It appears in every command's `--chdir` and in user-facing docs.
    assert_eq!(super::WORKSPACE_MOUNT, "/workspace");
    assert_eq!(
        args::workspace_dir(&spec()?)?,
        std::path::Path::new("/srv/work")
    );
    Ok(())
}
