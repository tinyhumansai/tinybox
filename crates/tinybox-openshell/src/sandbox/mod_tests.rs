//! Tests for the OpenShell sandbox.
//!
//! [`ScriptedHost`] records every command it is handed and replies from a
//! queue, so the whole backend runs without a gateway. Behavior that needs a
//! real gateway (that Landlock holds, that egress is denied) belongs to a live
//! suite, not here.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use tinybox_core::clock::FixedClock;
use tinybox_core::{
    Constraint, Enforcement, HostRef, MemoryStore, NetworkPolicy, Placement, SandboxRef,
    WorkspaceSource,
};

use super::*;

/// A host that records what it runs and answers from a script.
#[derive(Debug, Default)]
struct ScriptedHost {
    runs: Mutex<Vec<ExecRequest>>,
    replies: Mutex<VecDeque<Result<ExecOutput>>>,
}

impl ScriptedHost {
    fn new(replies: impl IntoIterator<Item = Result<ExecOutput>>) -> Arc<Self> {
        Arc::new(Self {
            runs: Mutex::default(),
            replies: Mutex::new(replies.into_iter().collect()),
        })
    }

    fn runs(&self) -> Vec<ExecRequest> {
        self.runs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn subcommands(&self) -> Vec<String> {
        self.runs()
            .iter()
            .map(|run| run.argv.get(2).cloned().unwrap_or_default())
            .collect()
    }
}

#[async_trait]
impl Host for ScriptedHost {
    fn name(&self) -> &'static str {
        "scripted"
    }

    async fn run(&self, request: &ExecRequest) -> Result<ExecOutput> {
        self.runs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(request.clone());
        self.replies
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop_front()
            .unwrap_or_else(|| Ok(ok("")))
    }
}

fn ok(stdout: &str) -> ExecOutput {
    ExecOutput::new(0, stdout.as_bytes().to_vec(), Vec::new())
}

fn failed(code: i32, stderr: &str) -> ExecOutput {
    ExecOutput::new(code, Vec::new(), stderr.as_bytes().to_vec())
}

fn phase(phase: &str) -> ExecOutput {
    ok(&format!(r#"{{"name":"tinybox-default-box-0","phase":"{phase}"}}"#))
}

fn spec() -> Result<BoxSpec> {
    Ok(BoxSpec::new(
        Placement::new(HostRef::new("local")?, SandboxRef::new(NAME)?),
        WorkspaceSource::OciImage("ghcr.io/example/agent:1".into()),
    ))
}

fn sandbox(host: &Arc<ScriptedHost>) -> (OpenShellSandbox, Arc<MemoryStore>) {
    let store = Arc::new(MemoryStore::new());
    (OpenShellSandbox::new(host.clone(), store.clone()), store)
}

#[test]
fn declares_kernel_isolation_and_nothing_it_cannot_do() {
    let capabilities = OpenShellSandbox::declared_capabilities();
    assert_eq!(capabilities.isolation, IsolationLevel::Kernel);
    assert!(capabilities.is_suitable_for_untrusted_code());
    assert!(capabilities.supports(Capability::ResourceLimits));
    for absent in [
        Capability::FilesystemSnapshot,
        Capability::Fork,
        Capability::PortForward,
        Capability::Detach,
    ] {
        assert!(!capabilities.supports(absent), "{absent}");
    }
}

#[test]
fn enforces_filesystem_network_cpu_and_memory_only() {
    let host = ScriptedHost::new([]);
    let (sandbox, _) = sandbox(&host);
    let support = sandbox.constraint_support();
    for enforced in [
        Constraint::Filesystem,
        Constraint::Network,
        Constraint::Cpu,
        Constraint::Memory,
    ] {
        assert_eq!(support.enforcement(enforced), Enforcement::Enforced, "{enforced}");
    }
    for unsupported in [Constraint::Pids, Constraint::Disk, Constraint::Subprocess] {
        assert_eq!(support.enforcement(unsupported), Enforcement::Unsupported, "{unsupported}");
    }
    assert_eq!(sandbox.name(), NAME);
}

#[test]
fn refuses_a_namespace_that_is_not_a_dns_label() {
    let host = ScriptedHost::new([]);
    let refused =
        OpenShellSandbox::with_namespace(host, Arc::new(MemoryStore::new()), "Not_Valid");
    assert!(matches!(refused, Err(Error::InvalidIdentifier { .. })));
}

#[tokio::test]
async fn creates_a_labelled_sandbox_and_records_the_box() -> Result<()> {
    let host = ScriptedHost::new([Ok(phase("Ready"))]);
    let store = Arc::new(MemoryStore::new());
    let created_at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
    let sandbox = OpenShellSandbox::with_namespace(host.clone(), store.clone(), "chottu")?
        .with_clock(Arc::new(FixedClock::at(created_at)))
        .with_policy("/etc/openshell/agent.yaml");

    let info = sandbox
        .create(&spec()?.with_env("TOKEN", "secret-value"))
        .await?;

    assert_eq!(info.state, BoxState::Ready);
    assert_eq!(info.created_at, Some(created_at));
    assert_eq!(store.get(&info.id)?.id, info.id);
    let runs = host.runs();
    assert_eq!(runs.len(), 1);
    let create = &runs[0];
    assert!(create.argv.contains(&"tinybox-chottu-box-0".to_owned()));
    assert!(create.argv.contains(&"/etc/openshell/agent.yaml".to_owned()));
    // The value rides in the CLI's environment, never its argv.
    assert_eq!(
        create.env.get("TOKEN").map(String::as_str),
        Some("secret-value")
    );
    Ok(())
}

#[tokio::test]
async fn a_refused_spec_runs_nothing_and_keeps_no_record() -> Result<()> {
    let host = ScriptedHost::new([]);
    let (sandbox, store) = sandbox(&host);

    let refused = sandbox
        .create(&spec()?.with_network(NetworkPolicy::Open))
        .await;

    assert!(matches!(refused, Err(Error::ConstraintNotEnforced { .. })));
    assert!(host.runs().is_empty());
    assert!(store.list()?.is_empty());
    Ok(())
}

#[tokio::test]
async fn an_invalid_spec_is_refused_before_any_record() -> Result<()> {
    let host = ScriptedHost::new([]);
    let (sandbox, store) = sandbox(&host);
    let zero_cpu = tinybox_core::Resources {
        cpu_millis: 0,
        ..tinybox_core::Resources::DEFAULT
    };

    let refused = sandbox.create(&spec()?.with_resources(zero_cpu)).await;

    assert!(matches!(refused, Err(Error::ZeroResourceLimit { .. })));
    assert!(store.list()?.is_empty());
    Ok(())
}

#[tokio::test]
async fn a_failed_create_deletes_the_sandbox_and_the_record() -> Result<()> {
    let host = ScriptedHost::new([
        Ok(failed(1, "sandbox did not become ready")),
        Ok(failed(1, "sandbox not found")),
    ]);
    let (sandbox, store) = sandbox(&host);

    let refused = sandbox.create(&spec()?).await;

    match refused {
        Err(Error::Backend { message, .. }) => {
            assert_eq!(message, "sandbox did not become ready");
        }
        other => return Err(unexpected(&other)),
    }
    assert_eq!(host.subcommands(), ["create", "delete"]);
    assert!(store.list()?.is_empty());
    Ok(())
}

#[tokio::test]
async fn a_failed_cleanup_after_a_failed_create_is_reported() -> Result<()> {
    let host = ScriptedHost::new([
        Ok(failed(1, "timed out")),
        Ok(failed(1, "connection refused")),
    ]);
    let (sandbox, store) = sandbox(&host);

    let refused = sandbox.create(&spec()?).await;

    match refused {
        Err(Error::Backend { operation, .. }) => assert_eq!(operation, "delete the sandbox"),
        other => return Err(unexpected(&other)),
    }
    assert!(store.list()?.is_empty());
    Ok(())
}

#[tokio::test]
async fn execs_in_a_ready_box_and_returns_the_commands_own_status() -> Result<()> {
    let host = ScriptedHost::new([
        Ok(phase("Ready")),
        Ok(phase("Ready")),
        Ok(failed(3, "boom")),
    ]);
    let (sandbox, _) = sandbox(&host);
    let info = sandbox.create(&spec()?).await?;

    let output = sandbox
        .exec(
            &info.id,
            &ExecRequest::new(["sh", "-c", "exit 3"]).with_stdin(b"input".to_vec()),
        )
        .await?;

    assert_eq!(output.exit_code, 3);
    assert_eq!(output.stderr_lossy(), "boom");
    assert_eq!(host.subcommands(), ["create", "get", "exec"]);
    let exec = host.runs().pop().ok_or_else(|| unexpected(&Ok::<(), Error>(())))?;
    assert_eq!(exec.stdin.as_deref(), Some(&b"input"[..]));
    Ok(())
}

#[tokio::test]
async fn refuses_to_exec_in_a_box_that_is_not_ready() -> Result<()> {
    let host = ScriptedHost::new([Ok(phase("Ready")), Ok(phase("Provisioning"))]);
    let (sandbox, _) = sandbox(&host);
    let info = sandbox.create(&spec()?).await?;

    let refused = sandbox.exec(&info.id, &ExecRequest::new(["true"])).await;

    assert!(matches!(
        refused,
        Err(Error::InvalidState {
            actual: BoxState::Creating,
            ..
        })
    ));
    assert_eq!(host.subcommands(), ["create", "get"]);
    Ok(())
}

#[tokio::test]
async fn reports_a_vanished_sandbox_as_archived() -> Result<()> {
    let host = ScriptedHost::new([Ok(phase("Ready")), Ok(failed(1, "Error: sandbox not found"))]);
    let (sandbox, _) = sandbox(&host);
    let info = sandbox.create(&spec()?).await?;

    assert_eq!(sandbox.inspect(&info.id).await?.state, BoxState::Archived);
    Ok(())
}

#[tokio::test]
async fn an_unreachable_gateway_is_an_error_not_a_state() -> Result<()> {
    let host = ScriptedHost::new([Ok(phase("Ready")), Ok(failed(1, "connection refused"))]);
    let (sandbox, _) = sandbox(&host);
    let info = sandbox.create(&spec()?).await?;

    let refused = sandbox.inspect(&info.id).await;

    assert!(matches!(refused, Err(Error::Backend { .. })));
    Ok(())
}

#[tokio::test]
async fn a_host_failure_while_inspecting_is_passed_through() -> Result<()> {
    let host = ScriptedHost::new([
        Ok(phase("Ready")),
        Err(Error::Io {
            operation: "spawn openshell",
            message: "no such file".to_owned(),
        }),
    ]);
    let (sandbox, _) = sandbox(&host);
    let info = sandbox.create(&spec()?).await?;

    assert!(matches!(
        sandbox.inspect(&info.id).await,
        Err(Error::Io { .. })
    ));
    Ok(())
}

#[tokio::test]
async fn destroys_the_sandbox_then_the_record() -> Result<()> {
    let host = ScriptedHost::new([Ok(phase("Ready")), Ok(ok(""))]);
    let (sandbox, store) = sandbox(&host);
    let info = sandbox.create(&spec()?).await?;

    sandbox.destroy(&info.id).await?;

    assert_eq!(host.subcommands(), ["create", "delete"]);
    assert!(store.list()?.is_empty());
    Ok(())
}

#[tokio::test]
async fn destroying_an_already_deleted_sandbox_succeeds() -> Result<()> {
    let host = ScriptedHost::new([Ok(phase("Ready")), Ok(failed(1, "sandbox not found"))]);
    let (sandbox, store) = sandbox(&host);
    let info = sandbox.create(&spec()?).await?;

    sandbox.destroy(&info.id).await?;

    assert!(store.list()?.is_empty());
    Ok(())
}

#[tokio::test]
async fn a_failed_delete_keeps_the_record() -> Result<()> {
    let host = ScriptedHost::new([Ok(phase("Ready")), Ok(failed(1, "permission denied"))]);
    let (sandbox, store) = sandbox(&host);
    let info = sandbox.create(&spec()?).await?;

    assert!(matches!(
        sandbox.destroy(&info.id).await,
        Err(Error::Backend { .. })
    ));
    assert_eq!(store.list()?.len(), 1);
    Ok(())
}

#[tokio::test]
async fn an_unknown_box_never_reaches_the_gateway() -> Result<()> {
    let host = ScriptedHost::new([]);
    let (sandbox, _) = sandbox(&host);
    let unknown = BoxId::new("box-9")?;

    assert!(matches!(
        sandbox.destroy(&unknown).await,
        Err(Error::UnknownBox { .. })
    ));
    assert!(matches!(
        sandbox.inspect(&unknown).await,
        Err(Error::UnknownBox { .. })
    ));
    assert!(host.runs().is_empty());
    Ok(())
}

#[tokio::test]
async fn refuses_snapshots_and_forks() -> Result<()> {
    let host = ScriptedHost::new([]);
    let (sandbox, _) = sandbox(&host);

    assert!(matches!(
        sandbox.snapshot(&BoxId::new("box-0")?).await,
        Err(Error::Unsupported {
            capability: Capability::FilesystemSnapshot,
            ..
        })
    ));
    assert!(matches!(
        sandbox.fork(&SnapshotId::new("sha-0")?, &spec()?).await,
        Err(Error::Unsupported {
            capability: Capability::Fork,
            ..
        })
    ));
    assert!(host.runs().is_empty());
    Ok(())
}

/// An error naming an outcome a test did not expect.
fn unexpected<T: std::fmt::Debug>(outcome: &Result<T>) -> Error {
    Error::Backend {
        sandbox: "test".to_owned(),
        operation: "match the expected outcome",
        message: format!("{outcome:?}"),
    }
}
