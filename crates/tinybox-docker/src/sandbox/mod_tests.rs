//! Tests for the Docker sandbox.
//!
//! [`ScriptedHost`] records every command it is handed and replies from a
//! queue, so the whole backend is exercised without a daemon. That is the point
//! of driving `docker` through a [`Host`]: the argv decisions — which limits
//! are applied, how a source becomes an image, what a digest turns into — are
//! the interesting part, and they are all assertable here.
//!
//! Behavior that genuinely needs a daemon lives in `tests/live_docker.rs`.

use std::collections::VecDeque;
use std::sync::{
    Arc, Mutex, MutexGuard, PoisonError,
    atomic::{AtomicBool, Ordering},
};

use async_trait::async_trait;
use tinybox_core::{
    BoxId, BoxSpec, BoxState, Capability, Error, ExecOutput, ExecRequest, Host, HostRef,
    IsolationLevel, MemoryStore, NetworkPolicy, Placement, PortMapping, Resources, Result, Sandbox,
    SandboxRef, SnapshotId, SnapshotSupport, Store, WorkspaceSource,
};

use super::{DockerSandbox, NAME, args, cleanup_timeout_error, state};

#[test]
fn effective_published_ports_parse_dynamic_and_fixed_bindings() -> Result<()> {
    let ports = args::parse_published_ports(
        r#"{"8080/tcp":[{"HostIp":"0.0.0.0","HostPort":"32768"}],"8443/tcp":[{"HostIp":"127.0.0.1","HostPort":"8443"}],"53/udp":null}"#,
    )?;

    assert_eq!(
        ports,
        [
            PortMapping {
                guest: 8080,
                host: Some(32768)
            },
            PortMapping {
                guest: 8443,
                host: Some(8443)
            }
        ]
    );
    assert!(args::parse_published_ports(r#"{"bad/tcp":[]}"#).is_err());
    assert!(args::parse_published_ports(r#"{"8080/tcp":[{"HostPort":"not-a-port"}]}"#).is_err());
    Ok(())
}

/// A digest `docker commit` might print.
const COMMIT_OUTPUT: &str =
    "sha256:9f2c0e1b7a4d5e6f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f";

/// A host that replays scripted replies and records what it was asked to run.
#[derive(Debug, Default)]
struct ScriptedHost {
    replies: Mutex<VecDeque<ExecOutput>>,
    seen: Mutex<Vec<Vec<String>>>,
    cancel_observed: AtomicBool,
    refuse_observed: AtomicBool,
    block_observed: AtomicBool,
    fail_next_reservation: AtomicBool,
    fail_next_abort: AtomicBool,
    fail_next_receipt_release: AtomicBool,
    fail_observed_cleanup: AtomicBool,
    observed_started: tokio::sync::Notify,
    release_observed: tokio::sync::Notify,
}

impl ScriptedHost {
    /// A host that answers every command with success and no output.
    fn silent() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn replies(&self) -> MutexGuard<'_, VecDeque<ExecOutput>> {
        self.replies.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn seen(&self) -> MutexGuard<'_, Vec<Vec<String>>> {
        self.seen.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Queue one reply, consumed by the next command.
    fn push(&self, output: ExecOutput) {
        self.replies().push_back(output);
    }

    /// Queue a successful reply printing `stdout`.
    fn push_ok(&self, stdout: &str) {
        self.push(ExecOutput::new(0, stdout.as_bytes().to_vec(), Vec::new()));
    }

    /// Queue a failing reply, as Docker would produce.
    fn push_failure(&self, stderr: &str) {
        self.push(ExecOutput::new(1, Vec::new(), stderr.as_bytes().to_vec()));
    }

    /// Every command run so far.
    fn commands(&self) -> Vec<Vec<String>> {
        self.seen().clone()
    }

    /// The nth command run, if it happened.
    fn command(&self, index: usize) -> Option<Vec<String>> {
        self.seen().get(index).cloned()
    }
}

#[async_trait]
impl Host for ScriptedHost {
    fn name(&self) -> &'static str {
        "scripted"
    }

    async fn run(&self, request: &ExecRequest) -> Result<ExecOutput> {
        self.seen().push(request.argv.clone());
        if request
            .argv
            .iter()
            .any(|argument| argument == "tinybox-observed-reserve")
        {
            if self.fail_next_reservation.swap(false, Ordering::AcqRel) {
                return Ok(ExecOutput::new(
                    125,
                    Vec::new(),
                    b"reservation refused".to_vec(),
                ));
            }
            return Ok(ExecOutput::new(0, b"ready\n".to_vec(), Vec::new()));
        }
        if request
            .argv
            .iter()
            .any(|argument| argument == "tinybox-observed-abort")
            && self.fail_next_abort.swap(false, Ordering::AcqRel)
        {
            return Ok(ExecOutput::new(1, Vec::new(), b"abort refused".to_vec()));
        }
        if request
            .argv
            .iter()
            .any(|argument| argument == "tinybox-observed-release")
            && self.fail_next_receipt_release.swap(false, Ordering::AcqRel)
        {
            return Ok(ExecOutput::new(
                1,
                Vec::new(),
                b"release reply lost".to_vec(),
            ));
        }
        if request
            .argv
            .iter()
            .any(|argument| argument == "tinybox-observed-cancel")
            && self.fail_observed_cleanup.load(Ordering::Acquire)
        {
            return Ok(ExecOutput::new(
                1,
                Vec::new(),
                b"container removed during observed cleanup".to_vec(),
            ));
        }
        let attempt_owner = if request
            .argv
            .iter()
            .any(|argument| argument.contains(args::OWNER_ATTEMPT_LABEL))
        {
            self.seen()
                .iter()
                .rev()
                .find_map(|command| {
                    command.windows(2).find_map(|pair| {
                        pair[0]
                            .eq("--label")
                            .then_some(pair[1].as_str())
                            .filter(|label| {
                                label.starts_with(&format!("{}=", args::OWNER_ATTEMPT_LABEL))
                            })
                    })
                })
                .and_then(|label| label.split_once('=').map(|(_, value)| value.to_owned()))
                .unwrap_or_default()
        } else {
            String::new()
        };
        Ok(self
            .replies()
            .pop_front()
            .unwrap_or_else(|| ExecOutput::new(0, attempt_owner.into_bytes(), Vec::new())))
    }

    async fn run_observed(
        &self,
        request: &ExecRequest,
        observer: Arc<dyn tinybox_core::ExecutionObserver>,
    ) -> Result<ExecOutput> {
        self.seen().push(request.argv.clone());
        if self.refuse_observed.load(Ordering::Acquire) {
            return Err(Error::UnsupportedStreaming {
                provider: self.name().to_owned(),
            });
        }
        if self.block_observed.load(Ordering::Acquire) {
            self.observed_started.notify_one();
            self.release_observed.notified().await;
        }
        if self.cancel_observed.load(Ordering::Acquire) {
            observer.cancelled().await;
            return Err(Error::Backend {
                sandbox: NAME.to_owned(),
                operation: "collect observed output",
                message: "execution cancelled".to_owned(),
            });
        }
        let output = self
            .replies()
            .pop_front()
            .unwrap_or_else(|| ExecOutput::new(0, Vec::new(), Vec::new()));
        if !output.stdout.is_empty() {
            observer.output(tinybox_core::OutputStream::Stdout, &output.stdout)?;
        }
        if !output.stderr.is_empty() {
            observer.output(tinybox_core::OutputStream::Stderr, &output.stderr)?;
        }
        Ok(output)
    }
}

/// A sandbox over a scripted host, plus a handle on the host and the store.
fn sandbox() -> (DockerSandbox, Arc<ScriptedHost>, Arc<MemoryStore>) {
    let host = ScriptedHost::silent();
    let store = Arc::new(MemoryStore::new());
    (DockerSandbox::new(host.clone(), store.clone()), host, store)
}

fn spec_from(source: WorkspaceSource) -> Result<BoxSpec> {
    Ok(BoxSpec::new(
        Placement::new(HostRef::new("local")?, SandboxRef::new(NAME)?),
        source,
    ))
}

fn spec() -> Result<BoxSpec> {
    spec_from(WorkspaceSource::OciImage("alpine:3".to_owned()))
}

/// The value following `flag` in a command line.
fn flag_value<'a>(argv: &'a [String], flag: &str) -> Option<&'a str> {
    argv.iter()
        .position(|part| part == flag)
        .and_then(|index| argv.get(index + 1))
        .map(String::as_str)
}

#[derive(Debug, Default)]
struct CapturingObserver {
    cancel: bool,
    batches: Mutex<Vec<(tinybox_core::OutputStream, Vec<u8>)>>,
}

impl CapturingObserver {
    fn batches(&self) -> Vec<(tinybox_core::OutputStream, Vec<u8>)> {
        self.batches
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

#[async_trait]
impl tinybox_core::ExecutionObserver for CapturingObserver {
    fn output(&self, stream: tinybox_core::OutputStream, bytes: &[u8]) -> Result<()> {
        self.batches
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((stream, bytes.to_vec()));
        Ok(())
    }

    async fn cancelled(&self) {
        if !self.cancel {
            std::future::pending::<()>().await;
        }
    }
}

#[test]
fn it_declares_kernel_isolation_and_filesystem_snapshots() {
    let caps = DockerSandbox::declared_capabilities();

    assert_eq!(caps.isolation, IsolationLevel::Kernel);
    assert_eq!(caps.snapshot, SnapshotSupport::Filesystem);
    // The first backend that is a defensible place for untrusted code.
    assert!(caps.is_suitable_for_untrusted_code());
    assert!(caps.supports(Capability::Fork));
    assert!(!caps.supports(Capability::ResourceLimits));
    // `docker pause` exists, but no trait method reaches it, so it is not
    // claimed.
    assert!(!caps.supports(Capability::PauseResume));
    assert!(!caps.supports(Capability::MemorySnapshot));
    // Ports are named in the spec and applied at creation, which is the only
    // moment a container can gain one — so this is a real claim.
    assert!(caps.supports(Capability::PortForward));
}

#[tokio::test]
async fn published_ports_reach_docker() -> Result<()> {
    let (sandbox, host, _store) = sandbox();
    let spec = spec()?
        .with_network(NetworkPolicy::Egress)
        .with_port(PortMapping::fixed(8080, 18080))
        .with_port(PortMapping::dynamic(9090));

    sandbox.create(&spec).await?;

    let argv = host.command(0).unwrap_or_default();
    let published = argv
        .iter()
        .enumerate()
        .filter(|(_, part)| part.as_str() == "--publish")
        .filter_map(|(index, _)| argv.get(index + 1).cloned())
        .collect::<Vec<_>>();

    // Ordered, because the spec holds them in a set: two specs differing only
    // in the order the ports were named produce the same command.
    assert_eq!(published, ["18080:8080", "9090"]);
    Ok(())
}

#[tokio::test]
async fn a_denied_network_publishes_nothing() -> Result<()> {
    let (sandbox, host, _store) = sandbox();
    // Denied is the default, so this is the spec someone gets by accident.
    let spec = spec()?.with_port(PortMapping::fixed(8080, 18080));

    sandbox.create(&spec).await?;

    let argv = host.command(0).unwrap_or_default();
    // A container with no network has nowhere for a published port to lead, and
    // Docker refuses the combination. The denial wins, being the stricter half.
    assert!(!argv.contains(&"--publish".to_owned()));
    assert_eq!(flag_value(&argv, "--network"), Some("none"));
    Ok(())
}

#[tokio::test]
async fn naming_the_same_port_twice_publishes_it_once() -> Result<()> {
    let (sandbox, host, _store) = sandbox();
    let spec = spec()?
        .with_network(NetworkPolicy::Open)
        .with_port(PortMapping::fixed(8080, 18080))
        .with_port(PortMapping::fixed(8080, 18080));

    sandbox.create(&spec).await?;

    let argv = host.command(0).unwrap_or_default();
    assert_eq!(
        argv.iter()
            .filter(|part| part.as_str() == "--publish")
            .count(),
        1
    );
    Ok(())
}

#[tokio::test]
async fn creating_a_box_runs_a_detached_named_labelled_container() -> Result<()> {
    let (sandbox, host, _store) = sandbox();

    let info = sandbox.create(&spec()?).await?;

    let argv = host.command(0).ok_or(Error::EmptyCommand {
        sandbox: NAME.to_owned(),
    })?;
    assert_eq!(argv[0], "docker");
    assert_eq!(argv[1], "run");
    assert!(argv.contains(&"--detach".to_owned()));
    assert_eq!(flag_value(&argv, "--name"), Some("tinybox-default-box-0"));
    assert_eq!(
        flag_value(&argv, "--label"),
        Some("ai.tinyhumans.tinybox=box-0")
    );
    // The image comes last before the keepalive command.
    assert!(argv.contains(&"alpine:3".to_owned()));
    assert_eq!(info.state, BoxState::Ready);
    Ok(())
}

#[tokio::test]
async fn an_image_that_looks_like_a_flag_stays_a_positional() -> Result<()> {
    let (sandbox, host, _store) = sandbox();

    sandbox
        .create(&spec_from(WorkspaceSource::OciImage(
            "--privileged".to_owned(),
        ))?)
        .await?;

    let argv = host.command(0).unwrap_or_default();
    let image = argv.iter().position(|part| part == "--privileged");
    assert_eq!(
        image
            .and_then(|index| argv.get(index - 1))
            .map(String::as_str),
        Some("--"),
        "{argv:?}"
    );
    Ok(())
}

#[tokio::test]
async fn the_container_is_held_open_so_commands_have_somewhere_to_land() -> Result<()> {
    let (sandbox, host, _store) = sandbox();

    sandbox.create(&spec()?).await?;

    let argv = host.command(0).unwrap_or_default();
    let tail = argv
        .iter()
        .skip_while(|part| *part != "alpine:3")
        .skip(1)
        .cloned()
        .collect::<Vec<_>>();

    // Without this the container would exit immediately and `docker exec` would
    // have nothing to attach to.
    assert_eq!(tail, ["sh", "-c", "while :; do sleep 86400; done"]);
    Ok(())
}

#[tokio::test]
async fn resource_limits_reach_docker() -> Result<()> {
    let (sandbox, host, _store) = sandbox();
    let spec = spec()?.with_resources(Resources {
        cpu_millis: 1_500,
        memory_bytes: 512 * 1024 * 1024,
        pids_max: 64,
        disk_bytes: 1024 * 1024 * 1024,
    });

    sandbox.create(&spec).await?;

    let argv = host.command(0).unwrap_or_default();
    assert_eq!(flag_value(&argv, "--memory"), Some("536870912b"));
    assert_eq!(flag_value(&argv, "--cpus"), Some("1.5"));
    assert_eq!(flag_value(&argv, "--pids-limit"), Some("64"));
    Ok(())
}

#[tokio::test]
async fn the_network_is_denied_by_default_and_opened_only_when_asked() -> Result<()> {
    let (sandbox, host, _store) = sandbox();

    sandbox.create(&spec()?).await?;
    let denied = host.command(0).unwrap_or_default();
    assert_eq!(flag_value(&denied, "--network"), Some("none"));

    sandbox
        .create(&spec()?.with_network(NetworkPolicy::Egress))
        .await?;
    let egress = host.command(1).unwrap_or_default();
    assert!(!egress.contains(&"--network".to_owned()));
    Ok(())
}

#[tokio::test]
async fn a_local_directory_is_bind_mounted_and_becomes_the_working_directory() -> Result<()> {
    let (sandbox, host, _store) = sandbox();

    sandbox
        .create(&spec_from(WorkspaceSource::LocalDir("/srv/work".into()))?)
        .await?;

    let argv = host.command(0).unwrap_or_default();
    assert_eq!(flag_value(&argv, "--volume"), Some("/srv/work:/workspace"));
    assert_eq!(flag_value(&argv, "--workdir"), Some("/workspace"));
    // A directory is not an image, so a base image supplies the userland.
    assert!(argv.contains(&"alpine:3".to_owned()));
    Ok(())
}

#[tokio::test]
async fn audit_high2_a_dangerous_local_directory_is_refused_before_any_record() -> Result<()> {
    let (sandbox, host, store) = sandbox();

    for path in ["/", "/etc", "/var/run"] {
        let outcome = sandbox
            .create(&spec_from(WorkspaceSource::LocalDir(path.into()))?)
            .await;
        assert_eq!(
            outcome.err(),
            Some(Error::UnsupportedWorkspaceSource {
                sandbox: NAME.to_owned(),
                kind: "dangerous host directory",
            }),
            "{path}"
        );
    }
    assert_eq!(store.list()?.len(), 0);
    assert!(host.command(0).is_none());
    Ok(())
}

#[tokio::test]
async fn a_persistent_box_cannot_gain_new_privileges() -> Result<()> {
    let (sandbox, host, _store) = sandbox();

    sandbox.create(&spec()?).await?;

    let argv = host.command(0).unwrap_or_default();
    assert_eq!(
        flag_value(&argv, "--security-opt"),
        Some("no-new-privileges")
    );
    Ok(())
}

#[tokio::test]
async fn box_environment_reaches_the_container() -> Result<()> {
    let (sandbox, host, _store) = sandbox();

    sandbox.create(&spec()?.with_env("CI", "true")).await?;

    let argv = host.command(0).unwrap_or_default();
    assert_eq!(flag_value(&argv, "--env"), Some("CI=true"));
    Ok(())
}

#[tokio::test]
async fn a_git_source_is_refused_before_anything_runs() -> Result<()> {
    let (sandbox, host, _store) = sandbox();

    let outcome = sandbox
        .create(&spec_from(WorkspaceSource::GitRepo {
            url: "https://example.invalid/repo.git".to_owned(),
            rev: "main".to_owned(),
        })?)
        .await;

    assert_eq!(
        outcome.err(),
        Some(Error::UnsupportedWorkspaceSource {
            sandbox: NAME.to_owned(),
            kind: "git repository",
        })
    );
    assert_eq!(host.commands().len(), 0, "nothing should have been run");
    Ok(())
}

#[tokio::test]
async fn a_docker_failure_carries_dockers_own_diagnostic() -> Result<()> {
    let (sandbox, host, store) = sandbox();
    host.push_failure("Unable to find image 'nope:1' locally");

    let outcome = sandbox
        .create(&spec_from(WorkspaceSource::OciImage("nope:1".to_owned()))?)
        .await;

    assert_eq!(
        outcome.err(),
        Some(Error::Backend {
            sandbox: NAME.to_owned(),
            operation: "create the container",
            message: "Unable to find image 'nope:1' locally".to_owned(),
        })
    );
    // A container that was never created must leave no record.
    assert_eq!(store.list()?.len(), 0);
    Ok(())
}

#[tokio::test]
async fn a_name_conflict_never_removes_the_existing_container() -> Result<()> {
    let host = ScriptedHost::silent();
    let first_store = Arc::new(MemoryStore::new());
    let second_store = Arc::new(MemoryStore::new());
    let first = DockerSandbox::new(host.clone(), first_store.clone());
    let second = DockerSandbox::new(host.clone(), second_store.clone());
    first.create(&spec()?).await?;
    host.push_failure("Conflict. The container name \"/tinybox-default-box-0\" is already in use");

    let outcome = second.create(&spec()?).await;

    assert!(outcome.is_err());
    let commands = host.commands();
    assert_eq!(commands.len(), 2, "a name conflict must not run rm");
    assert!(commands.iter().all(|command| command[1] == "run"));
    assert_eq!(first_store.list()?.len(), 1);
    assert_eq!(second_store.list()?.len(), 0);
    Ok(())
}

#[tokio::test]
async fn a_lost_create_reply_removes_only_our_verified_create_attempt() -> Result<()> {
    let (sandbox, host, store) = sandbox();
    host.push_failure("connection reset after create");

    assert!(sandbox.create(&spec()?).await.is_err());

    let commands = host.commands();
    assert_eq!(commands.len(), 3);
    assert_eq!(commands[1][1], "container");
    assert_eq!(commands[1][2], "inspect");
    assert!(commands[1][4].contains(args::OWNER_ATTEMPT_LABEL));
    assert_eq!(commands[2][1], "rm");
    assert_eq!(store.list()?.len(), 0);
    Ok(())
}

#[tokio::test]
async fn failed_create_ownership_probe_uses_container_specific_inspection() -> Result<()> {
    let store = Arc::new(MemoryStore::new());
    let sandbox = DockerSandbox::new(Arc::new(MissingContainerHost), store.clone());
    assert!(sandbox.create(&spec()?).await.is_err());
    assert_eq!(store.list()?.len(), 0);
    Ok(())
}

/// Model the Docker CLI's different missing-object diagnostics, without a daemon.
#[derive(Debug)]
struct MissingContainerHost;

#[async_trait]
impl Host for MissingContainerHost {
    fn name(&self) -> &'static str {
        "scripted"
    }

    async fn run(&self, request: &ExecRequest) -> Result<ExecOutput> {
        let error = match request.argv.get(1).map(String::as_str) {
            Some("run") => "image download failed",
            Some("container") => "Error: No such container: tinybox-default-box-0",
            _ => "Error: No such object: tinybox-default-box-0",
        };
        Ok(ExecOutput::new(1, Vec::new(), error.as_bytes().to_vec()))
    }
}

#[tokio::test]
async fn a_lost_create_reply_leaves_a_foreign_container_untouched() -> Result<()> {
    let (sandbox, host, store) = sandbox();
    host.push_failure("connection reset after create");
    host.push_ok("different-owner");

    assert!(sandbox.create(&spec()?).await.is_err());

    let commands = host.commands();
    assert_eq!(commands.len(), 2);
    assert_eq!(commands[1][1], "container");
    assert_eq!(commands[1][2], "inspect");
    assert_eq!(store.list()?.len(), 0);
    Ok(())
}

#[tokio::test]
async fn a_same_id_container_from_another_attempt_is_not_removed() -> Result<()> {
    let (sandbox, host, store) = sandbox();
    host.push_failure("connection reset after create");
    host.push_ok("box-0"); // matching box id, but not the per-attempt token

    assert!(sandbox.create(&spec()?).await.is_err());

    let commands = host.commands();
    assert_eq!(commands.len(), 2);
    assert_eq!(commands[1][1], "container");
    assert_eq!(commands[1][2], "inspect");
    assert_eq!(store.list()?.len(), 0);
    Ok(())
}

#[tokio::test]
async fn a_command_runs_inside_the_container() -> Result<()> {
    let (sandbox, host, _store) = sandbox();
    let info = sandbox.create(&spec()?).await?;
    host.push_ok("running"); // inspect
    host.push(ExecOutput::new(0, b"hello\n".to_vec(), Vec::new()));

    let output = sandbox
        .exec(&info.id, &ExecRequest::new(["echo", "hello"]))
        .await?;

    assert_eq!(output.stdout_lossy().trim(), "hello");
    let argv = host.command(2).unwrap_or_default();
    assert_eq!(argv[0..2], ["docker", "exec"]);
    // The container name is the last flag-like argument; everything after it is
    // the command, so a user argument can never be read as a docker flag.
    let name_at = argv.iter().position(|part| part == "tinybox-default-box-0");
    assert_eq!(
        name_at.map(|index| &argv[index + 1..]),
        Some(&["echo".to_owned(), "hello".to_owned()][..])
    );
    Ok(())
}

#[tokio::test]
async fn a_failing_command_is_a_result_not_a_backend_error() -> Result<()> {
    let (sandbox, host, _store) = sandbox();
    let info = sandbox.create(&spec()?).await?;
    host.push_ok("running");
    host.push(ExecOutput::new(7, Vec::new(), b"boom\n".to_vec()));

    // A command that runs and fails is an outcome; only a failed *docker
    // invocation* is a backend error.
    let output = sandbox.exec(&info.id, &ExecRequest::new(["false"])).await?;

    assert_eq!(output.exit_code, 7);
    assert_eq!(output.stderr_lossy().trim(), "boom");
    Ok(())
}

#[tokio::test]
async fn a_command_carries_its_working_directory_and_environment() -> Result<()> {
    let (sandbox, host, _store) = sandbox();
    let info = sandbox.create(&spec()?).await?;
    host.push_ok("running");

    sandbox
        .exec(
            &info.id,
            &ExecRequest::new(["pwd"])
                .with_cwd("/tmp")
                .with_env("K", "v"),
        )
        .await?;

    let argv = host.command(2).unwrap_or_default();
    assert_eq!(flag_value(&argv, "--workdir"), Some("/tmp"));
    assert_eq!(flag_value(&argv, "--env"), Some("K=v"));
    Ok(())
}

#[tokio::test]
async fn observed_command_forwards_live_bytes_and_waits_for_remote_ack() -> Result<()> {
    let (sandbox, host, _store) = sandbox();
    let info = sandbox.create(&spec()?).await?;
    host.push_ok("running");
    host.push(ExecOutput::new(9, vec![0, 255], b"failure".to_vec()));
    host.push_ok(""); // Remote waiter acknowledgement and control-dir cleanup.
    let observer = Arc::new(CapturingObserver::default());

    let output = sandbox
        .exec_observed(
            &info.id,
            &ExecRequest::new(["binary-command"]),
            observer.clone(),
        )
        .await?;

    assert_eq!(output.exit_code, 9);
    assert_eq!(output.stdout, [0, 255]);
    assert_eq!(output.stderr, b"failure");
    assert_eq!(
        observer.batches(),
        [
            (tinybox_core::OutputStream::Stdout, vec![0, 255]),
            (tinybox_core::OutputStream::Stderr, b"failure".to_vec()),
        ]
    );
    assert!(!sandbox.has_pending_observed_cleanup());
    let observed_command = host.command(3).unwrap_or_default();
    assert_eq!(observed_command[0..3], ["docker", "exec", "-i"]);
    assert!(observed_command.iter().any(|arg| arg == "binary-command"));
    Ok(())
}

#[tokio::test]
async fn failed_remote_ack_is_retained_and_retried_without_waiting_for_runs() -> Result<()> {
    let (sandbox, host, _store) = sandbox();
    let info = sandbox.create(&spec()?).await?;
    host.push_ok("running");
    host.push_failure("container waiter did not acknowledge");
    host.cancel_observed.store(true, Ordering::Release);
    let observer = Arc::new(CapturingObserver {
        cancel: true,
        ..CapturingObserver::default()
    });

    let result = sandbox
        .exec_observed(&info.id, &ExecRequest::new(["long-running"]), observer)
        .await;

    assert_eq!(
        result.err(),
        Some(Error::ObservedCleanupPending {
            provider: NAME.to_owned(),
        })
    );
    assert!(sandbox.has_pending_observed_cleanup());

    host.push_ok("");
    sandbox.retry_observed_cleanup().await?;

    assert!(!sandbox.has_pending_observed_cleanup());
    Ok(())
}

#[tokio::test]
async fn unstarted_reservation_cleanup_is_retained_and_retried() -> Result<()> {
    let (sandbox, host, _store) = sandbox();
    let info = sandbox.create(&spec()?).await?;
    host.push_ok("running");
    host.fail_next_reservation.store(true, Ordering::Release);
    host.fail_next_abort.store(true, Ordering::Release);

    let result = sandbox
        .exec_observed(
            &info.id,
            &ExecRequest::new(["not-dispatched"]),
            Arc::new(CapturingObserver::default()),
        )
        .await;

    assert_eq!(
        result.err(),
        Some(Error::ObservedCleanupPending {
            provider: NAME.to_owned(),
        })
    );
    assert!(sandbox.has_pending_observed_cleanup());
    assert!(
        !host
            .commands()
            .iter()
            .any(|command| command.iter().any(|argument| argument == "not-dispatched"))
    );

    sandbox.retry_observed_cleanup().await?;
    assert!(!sandbox.has_pending_observed_cleanup());
    Ok(())
}

#[tokio::test]
async fn a_lost_receipt_release_reply_retries_without_reacknowledging_cleanup() -> Result<()> {
    let (sandbox, host, _store) = sandbox();
    let info = sandbox.create(&spec()?).await?;
    host.push_ok("running");
    host.fail_next_receipt_release
        .store(true, Ordering::Release);
    host.cancel_observed.store(true, Ordering::Release);

    let result = sandbox
        .exec_observed(
            &info.id,
            &ExecRequest::new(["long-running"]),
            Arc::new(CapturingObserver {
                cancel: true,
                ..CapturingObserver::default()
            }),
        )
        .await;

    assert_eq!(
        result.err(),
        Some(Error::ObservedCleanupPending {
            provider: NAME.to_owned(),
        })
    );
    let commands_before_retry = host.commands();
    assert_eq!(
        commands_before_retry
            .iter()
            .filter(|command| command
                .iter()
                .any(|argument| argument == "tinybox-observed-cancel"))
            .count(),
        1
    );

    sandbox.retry_observed_cleanup().await?;
    assert!(!sandbox.has_pending_observed_cleanup());
    let commands_after_retry = host.commands();
    assert_eq!(
        commands_after_retry
            .iter()
            .filter(|command| command
                .iter()
                .any(|argument| argument == "tinybox-observed-cancel"))
            .count(),
        1
    );
    assert_eq!(
        commands_after_retry
            .iter()
            .filter(|command| command
                .iter()
                .any(|argument| argument == "tinybox-observed-release"))
            .count(),
        2
    );
    Ok(())
}

#[test]
fn observed_cleanup_timeout_has_a_typed_diagnostic() {
    assert_eq!(
        cleanup_timeout_error(),
        Error::Backend {
            sandbox: NAME.to_owned(),
            operation: "acknowledge observed execution cleanup",
            message: "container-side waiter did not acknowledge cleanup before the deadline"
                .to_owned(),
        }
    );
}

#[tokio::test]
async fn a_failed_remote_ack_reply_is_retained_until_retry_succeeds() -> Result<()> {
    let (sandbox, host, _store) = sandbox();
    let info = sandbox.create(&spec()?).await?;
    host.push_ok("running");
    host.push(ExecOutput::new(
        1,
        Vec::new(),
        b"waiter did not finish cleanup".to_vec(),
    ));
    host.cancel_observed.store(true, Ordering::Release);

    let result = sandbox
        .exec_observed(
            &info.id,
            &ExecRequest::new(["long-running"]),
            Arc::new(CapturingObserver {
                cancel: true,
                ..CapturingObserver::default()
            }),
        )
        .await;

    assert_eq!(
        result.err(),
        Some(Error::ObservedCleanupPending {
            provider: NAME.to_owned(),
        })
    );
    assert!(sandbox.has_pending_observed_cleanup());
    host.push_ok("");
    sandbox.retry_observed_cleanup().await?;
    assert!(!sandbox.has_pending_observed_cleanup());
    Ok(())
}

#[tokio::test]
async fn destroying_a_container_retires_its_failed_observed_cleanup() -> Result<()> {
    let (sandbox, host, _store) = sandbox();
    let info = sandbox.create(&spec()?).await?;
    host.push_ok("running");
    host.push_failure("container waiter did not acknowledge");
    host.cancel_observed.store(true, Ordering::Release);
    let result = sandbox
        .exec_observed(
            &info.id,
            &ExecRequest::new(["long-running"]),
            Arc::new(CapturingObserver {
                cancel: true,
                ..CapturingObserver::default()
            }),
        )
        .await;
    assert_eq!(
        result.err(),
        Some(Error::ObservedCleanupPending {
            provider: NAME.to_owned(),
        })
    );
    assert!(sandbox.has_pending_observed_cleanup());

    host.push_ok("");
    sandbox.destroy(&info.id).await?;

    assert!(!sandbox.has_pending_observed_cleanup());
    Ok(())
}

#[tokio::test]
async fn unavailable_host_observation_does_not_fall_back_to_collected_exec() -> Result<()> {
    let (sandbox, host, _store) = sandbox();
    let info = sandbox.create(&spec()?).await?;
    host.push_ok("running");
    host.refuse_observed.store(true, Ordering::Release);
    let calls_before = host.commands().len();

    let error = sandbox
        .exec_observed(
            &info.id,
            &ExecRequest::new(["must-not-run-collected"]),
            Arc::new(CapturingObserver::default()),
        )
        .await
        .err();

    assert_eq!(
        error,
        Some(Error::UnsupportedStreaming {
            provider: "scripted".to_owned(),
        })
    );
    assert_eq!(host.commands().len(), calls_before + 5); // Inspect, reservation, refused call, retry reservation, release.
    assert!(!sandbox.has_pending_observed_cleanup());
    Ok(())
}

#[tokio::test]
async fn image_without_process_group_support_fails_closed() -> Result<()> {
    let (sandbox, host, _store) = sandbox();
    let info = sandbox.create(&spec()?).await?;
    host.push_ok("running");
    host.push(ExecOutput::new(125, Vec::new(), Vec::new()));
    host.push_ok("unsupported");

    let result = sandbox
        .exec_observed(
            &info.id,
            &ExecRequest::new(["must-not-run"]),
            Arc::new(CapturingObserver::default()),
        )
        .await;

    assert_eq!(
        result.err(),
        Some(Error::UnsupportedStreaming {
            provider: NAME.to_owned(),
        })
    );
    assert!(!sandbox.has_pending_observed_cleanup());
    Ok(())
}

#[tokio::test]
async fn active_observed_execution_is_not_reported_as_pending_cleanup() -> Result<()> {
    let (sandbox, host, _store) = sandbox();
    let info = sandbox.create(&spec()?).await?;
    host.push_ok("running");
    host.push_ok(""); // Remote waiter acknowledgement after the command returns.
    host.block_observed.store(true, Ordering::Release);
    let sandbox = Arc::new(sandbox);
    let running = {
        let sandbox = sandbox.clone();
        let id = info.id.clone();
        tokio::spawn(async move {
            sandbox
                .exec_observed(
                    &id,
                    &ExecRequest::new(["still-running"]),
                    Arc::new(CapturingObserver::default()),
                )
                .await
        })
    };

    host.observed_started.notified().await;
    assert!(!sandbox.has_pending_observed_cleanup());
    host.release_observed.notify_one();
    running.await.map_err(|error| Error::Backend {
        sandbox: NAME.to_owned(),
        operation: "join observed fixture",
        message: error.to_string(),
    })??;

    Ok(())
}

#[tokio::test]
async fn observed_host_view_reuses_container_identity_and_isolates_cleanup_state() -> Result<()> {
    let host = ScriptedHost::silent();
    let store = Arc::new(MemoryStore::new());
    let sandbox = DockerSandbox::with_namespace(host.clone(), store, "team")?;
    let info = sandbox.create(&spec()?).await?;
    let execution_host = ScriptedHost::silent();
    execution_host.push_ok("running"); // Inspect the existing container on this host.
    execution_host.push_failure("container waiter did not acknowledge");
    execution_host
        .cancel_observed
        .store(true, Ordering::Release);
    let execution_sandbox = sandbox.for_observed_host(execution_host.clone());

    let result = execution_sandbox
        .exec_observed(
            &info.id,
            &ExecRequest::new(["long-running"]),
            Arc::new(CapturingObserver {
                cancel: true,
                ..CapturingObserver::default()
            }),
        )
        .await;

    assert_eq!(
        result.err(),
        Some(Error::ObservedCleanupPending {
            provider: NAME.to_owned(),
        })
    );
    assert!(execution_sandbox.has_pending_observed_cleanup());
    assert!(!sandbox.has_pending_observed_cleanup());
    let observed_argv = execution_host.command(2).unwrap_or_default();
    assert_eq!(observed_argv[0..3], ["docker", "exec", "-i"]);
    assert!(observed_argv.iter().any(|arg| arg == "tinybox-team-box-0"));

    let original_calls = host.commands().len();
    sandbox.retry_observed_cleanup().await?;
    assert_eq!(host.commands().len(), original_calls);

    let execution_calls = execution_host.commands().len();
    sandbox.destroy(&info.id).await?;
    assert!(execution_sandbox.has_pending_observed_cleanup());
    execution_sandbox.acknowledge_observed_cleanup_for_destroyed_box(&info.id);
    assert!(!execution_sandbox.has_pending_observed_cleanup());
    assert_eq!(execution_host.commands().len(), execution_calls);
    Ok(())
}

#[tokio::test]
async fn confirmed_destroy_prevents_a_late_observed_cleanup_handle_from_being_retained()
-> Result<()> {
    let (sandbox, host, store) = sandbox();
    let info = sandbox.create(&spec()?).await?;
    let observed_view = sandbox.for_observed_host(host.clone());
    host.push_ok("running");
    host.block_observed.store(true, Ordering::Release);
    host.fail_observed_cleanup.store(true, Ordering::Release);

    let execution_view = observed_view.clone();
    let id = info.id.clone();
    let execution = tokio::spawn(async move {
        execution_view
            .exec_observed(
                &id,
                &ExecRequest::new(["long-running-command"]),
                Arc::new(CapturingObserver {
                    cancel: true,
                    ..CapturingObserver::default()
                }),
            )
            .await
    });
    tokio::time::timeout(
        std::time::Duration::from_secs(3),
        host.observed_started.notified(),
    )
    .await
    .map_err(|_| Error::Backend {
        sandbox: NAME.to_owned(),
        operation: "start concurrent observed-destroy fixture",
        message: "observed execution did not reach the host".to_owned(),
    })?;

    // Destruction confirms that Docker removed the complete container while
    // the per-execution host view is still waiting for its observed reply.
    sandbox.destroy(&info.id).await?;
    assert_eq!(store.list()?.len(), 0);
    host.cancel_observed.store(true, Ordering::Release);
    host.release_observed.notify_one();

    let result = tokio::time::timeout(std::time::Duration::from_secs(3), execution)
        .await
        .map_err(|_| Error::Backend {
            sandbox: NAME.to_owned(),
            operation: "finish concurrent observed-destroy fixture",
            message: "observed execution did not finish after the host reply".to_owned(),
        })?
        .map_err(|error| Error::Backend {
            sandbox: NAME.to_owned(),
            operation: "join concurrent observed-destroy fixture",
            message: error.to_string(),
        })?;
    assert!(result.is_err());
    assert!(!observed_view.has_pending_observed_cleanup());
    Ok(())
}

#[tokio::test]
async fn a_command_with_no_program_is_refused() -> Result<()> {
    let (sandbox, host, _store) = sandbox();
    let info = sandbox.create(&spec()?).await?;
    host.push_ok("running");

    let empty: Vec<String> = Vec::new();
    assert_eq!(
        sandbox.exec(&info.id, &ExecRequest::new(empty)).await.err(),
        Some(Error::EmptyCommand {
            sandbox: NAME.to_owned()
        })
    );
    Ok(())
}

#[tokio::test]
async fn a_stopped_container_accepts_no_commands() -> Result<()> {
    let (sandbox, host, _store) = sandbox();
    let info = sandbox.create(&spec()?).await?;
    host.push_ok("exited");

    assert_eq!(
        sandbox
            .exec(&info.id, &ExecRequest::new(["true"]))
            .await
            .err(),
        Some(Error::InvalidState {
            id: "box-0".to_owned(),
            actual: BoxState::Stopped,
            expected: BoxState::Ready,
        })
    );
    Ok(())
}

#[tokio::test]
async fn a_nonzero_detached_stop_is_reported_as_unfinished_cleanup() -> Result<()> {
    let (sandbox, host, _store) = sandbox();
    let info = sandbox.create(&spec()?).await?;
    let process = tinybox_core::ProcessId::new("process-1")?;
    host.push_ok("running");
    host.push_failure("process cleanup was refused");

    assert_eq!(
        sandbox.stop(&info.id, &process).await.err(),
        Some(Error::Backend {
            sandbox: NAME.to_owned(),
            operation: "stop a detached process",
            message: "process cleanup was refused".to_owned(),
        })
    );
    Ok(())
}

#[tokio::test]
async fn a_lost_create_reply_retains_the_record_until_named_cleanup_is_acknowledged() -> Result<()>
{
    let (sandbox, host, store) = sandbox();
    host.push_failure("docker connection was interrupted");
    host.push_failure("daemon temporarily unavailable");

    assert!(sandbox.create(&spec()?).await.is_err());
    assert_eq!(store.list()?.len(), 1);

    sandbox.destroy(&BoxId::new("box-0")?).await?;
    assert_eq!(store.list()?.len(), 0);
    Ok(())
}

#[tokio::test]
async fn a_lost_create_reply_releases_the_record_after_named_cleanup_succeeds() -> Result<()> {
    let (sandbox, host, store) = sandbox();
    host.push_failure("docker connection was interrupted");

    assert!(sandbox.create(&spec()?).await.is_err());

    assert_eq!(store.list()?.len(), 0);
    let commands = host.commands();
    assert_eq!(commands.len(), 3);
    assert_eq!(commands[0].get(1).map(String::as_str), Some("run"));
    assert_eq!(commands[1].get(1).map(String::as_str), Some("container"));
    assert_eq!(commands[1].get(2).map(String::as_str), Some("inspect"));
    assert_eq!(commands[2].get(1).map(String::as_str), Some("rm"));
    Ok(())
}

#[tokio::test]
async fn a_missing_named_container_completes_destroy_cleanup() -> Result<()> {
    let (sandbox, host, store) = sandbox();
    let info = sandbox.create(&spec()?).await?;
    host.push_failure("Error: No such container: tinybox-default-box-0");

    sandbox.destroy(&info.id).await?;

    assert_eq!(store.list()?.len(), 0);
    Ok(())
}

#[tokio::test]
async fn inspect_reports_the_containers_real_state_not_the_record() -> Result<()> {
    let (sandbox, host, _store) = sandbox();
    let info = sandbox.create(&spec()?).await?;
    // The record says Ready; Docker says the container stopped.
    host.push_ok("exited");

    let inspected = sandbox.inspect(&info.id).await?;

    // Trusting the record here would send commands to a box that is gone.
    assert_eq!(inspected.state, BoxState::Stopped);
    assert_eq!(inspected.spec, info.spec);
    Ok(())
}

#[tokio::test]
async fn a_container_removed_behind_our_back_reads_as_archived() -> Result<()> {
    let (sandbox, host, _store) = sandbox();
    let info = sandbox.create(&spec()?).await?;
    host.push_failure("Error: No such object: tinybox-box-0");

    // The record outliving the container is a real state, not an error.
    assert_eq!(sandbox.inspect(&info.id).await?.state, BoxState::Archived);
    Ok(())
}

#[tokio::test]
async fn snapshotting_commits_the_container_and_shortens_the_digest() -> Result<()> {
    let (sandbox, host, _store) = sandbox();
    let info = sandbox.create(&spec()?).await?;
    host.push_ok(COMMIT_OUTPUT);

    let snapshot = sandbox.snapshot(&info.id).await?;

    assert_eq!(
        host.command(1).unwrap_or_default()[0..2],
        ["docker", "commit"]
    );
    // `sha256:<64 hex>` is not a valid tinybox identifier, so a short prefixed
    // form is used — and Docker still resolves it as an image reference.
    assert_eq!(snapshot.as_str(), "sha-9f2c0e1b7a4d");
    Ok(())
}

#[tokio::test]
async fn an_unreadable_commit_digest_is_reported() -> Result<()> {
    let (sandbox, host, _store) = sandbox();
    let info = sandbox.create(&spec()?).await?;
    host.push_ok("not a digest at all");

    assert!(matches!(
        sandbox.snapshot(&info.id).await,
        Err(Error::Backend {
            operation: "read the committed image digest",
            ..
        })
    ));
    Ok(())
}

#[tokio::test]
async fn forking_starts_a_container_from_the_snapshot_image() -> Result<()> {
    let (sandbox, host, _store) = sandbox();
    let info = sandbox.create(&spec()?).await?;
    host.push_ok(COMMIT_OUTPUT);
    let snapshot = sandbox.snapshot(&info.id).await?;

    let forked = sandbox.fork(&snapshot, &spec()?).await?;

    assert_ne!(forked.id, info.id);
    let argv = host.command(2).unwrap_or_default();
    // The snapshot replaces the spec's own source, and the short digest is what
    // Docker is handed.
    assert!(argv.contains(&"9f2c0e1b7a4d".to_owned()));
    assert!(!argv.contains(&"alpine:3".to_owned()));
    Ok(())
}

#[tokio::test]
async fn destroying_a_box_removes_the_container_before_the_record() -> Result<()> {
    let (sandbox, host, store) = sandbox();
    let info = sandbox.create(&spec()?).await?;

    sandbox.destroy(&info.id).await?;

    let argv = host.command(1).unwrap_or_default();
    assert_eq!(argv[0..2], ["docker", "rm"]);
    assert!(argv.contains(&"--force".to_owned()));
    assert!(argv.contains(&"--volumes".to_owned()));
    assert_eq!(store.list()?.len(), 0);
    Ok(())
}

#[tokio::test]
async fn a_container_that_will_not_go_away_keeps_its_record() -> Result<()> {
    let (sandbox, host, store) = sandbox();
    let info = sandbox.create(&spec()?).await?;
    host.push_failure("permission denied");

    assert!(sandbox.destroy(&info.id).await.is_err());
    // A record without a container is recoverable; a container without a record
    // is a leak, so the record stays until the container is really gone.
    assert_eq!(store.list()?.len(), 1);
    Ok(())
}

#[tokio::test]
async fn an_unknown_box_is_reported_without_touching_docker() -> Result<()> {
    let (sandbox, host, _store) = sandbox();
    let missing = BoxId::new("absent")?;
    let expected = Some(Error::UnknownBox {
        id: "absent".to_owned(),
    });

    assert_eq!(sandbox.inspect(&missing).await.err(), expected);
    assert_eq!(sandbox.destroy(&missing).await.err(), expected);
    assert_eq!(sandbox.snapshot(&missing).await.err(), expected);
    assert_eq!(host.commands().len(), 0);
    Ok(())
}

#[tokio::test]
async fn an_invalid_spec_never_reaches_docker() -> Result<()> {
    let (sandbox, host, _store) = sandbox();
    let spec = spec()?.with_resources(Resources {
        memory_bytes: 0,
        ..Resources::DEFAULT
    });

    assert_eq!(
        sandbox.create(&spec).await.err(),
        Some(Error::ZeroResourceLimit {
            limit: "memory_bytes"
        })
    );
    assert_eq!(host.commands().len(), 0);
    Ok(())
}

#[tokio::test]
async fn it_is_usable_behind_a_trait_object() -> Result<()> {
    let sandbox: Box<dyn Sandbox> = Box::new(DockerSandbox::new(
        ScriptedHost::silent(),
        Arc::new(MemoryStore::new()),
    ));

    assert_eq!(sandbox.name(), "docker");
    assert!(sandbox.capabilities().is_suitable_for_untrusted_code());
    assert_eq!(sandbox.create(&spec()?).await?.state, BoxState::Ready);
    Ok(())
}

#[test]
fn docker_statuses_map_onto_box_states() {
    // `running` is Ready, not Running: a tinybox box is Running when a command
    // is executing, and the keepalive loop is not a command.
    assert_eq!(state::from_docker("running"), BoxState::Ready);
    assert_eq!(state::from_docker("paused"), BoxState::Paused);
    assert_eq!(state::from_docker("created"), BoxState::Stopped);
    assert_eq!(state::from_docker("exited"), BoxState::Stopped);
    assert_eq!(state::from_docker("restarting"), BoxState::Creating);
    assert_eq!(state::from_docker("removing"), BoxState::Archived);
    // Anything outside Docker's small vocabulary is a problem worth surfacing.
    assert_eq!(state::from_docker("dead"), BoxState::Failed);
    assert_eq!(state::from_docker("something-new"), BoxState::Failed);
    // Docker's output arrives with a trailing newline.
    assert_eq!(state::from_docker("  running \n"), BoxState::Ready);
}

#[test]
fn a_snapshot_identifier_round_trips_to_an_image_reference() -> Result<()> {
    let snapshot = args::snapshot_of_commit(COMMIT_OUTPUT)?;

    assert_eq!(args::image_of_snapshot(&snapshot), "9f2c0e1b7a4d");
    // A bare identifier that was never produced here is passed through rather
    // than mangled.
    assert_eq!(
        args::image_of_snapshot(&SnapshotId::new("alpine.3")?),
        "alpine.3"
    );
    Ok(())
}

#[test]
fn a_commit_digest_is_parsed_leniently_but_validated() -> Result<()> {
    // Trailing whitespace is normal; a bare digest without the algorithm prefix
    // is accepted too, since that is a plausible future output format.
    assert_eq!(
        args::snapshot_of_commit("  sha256:abcdef0123456789  \n")?.as_str(),
        "sha-abcdef012345"
    );

    for bad in ["", "sha256:", "sha256:xyz", "sha256:abc"] {
        assert!(
            args::snapshot_of_commit(bad).is_err(),
            "{bad:?} should be rejected"
        );
    }
    Ok(())
}

#[test]
fn container_names_are_namespaced_so_two_stores_do_not_collide() -> Result<()> {
    // Two stores both allocate `box-0`; only the namespace keeps their
    // containers apart on one daemon.
    assert_ne!(
        args::container_name("alice", &BoxId::new("box-0")?),
        args::container_name("bob", &BoxId::new("box-0")?)
    );
    assert_eq!(
        args::container_name("default", &BoxId::new("box-0")?),
        "tinybox-default-box-0"
    );
    Ok(())
}

/// A host that cannot run anything, standing in for a machine that is
/// unreachable or has no `docker` binary.
#[derive(Debug)]
struct BrokenHost;

#[async_trait]
impl Host for BrokenHost {
    fn name(&self) -> &'static str {
        "broken"
    }

    async fn run(&self, _request: &ExecRequest) -> Result<ExecOutput> {
        Err(Error::Io {
            operation: "spawn",
            message: "no such file or directory".to_owned(),
        })
    }
}

#[tokio::test]
async fn a_host_that_cannot_run_docker_reports_that_rather_than_a_backend_error() -> Result<()> {
    let sandbox = DockerSandbox::new(Arc::new(BrokenHost), Arc::new(MemoryStore::new()));

    // A missing `docker` binary is the host failing to start something, not
    // Docker refusing — the two are different problems with different fixes.
    assert!(matches!(
        sandbox.create(&spec()?).await,
        Err(Error::Io {
            operation: "spawn",
            ..
        })
    ));
    Ok(())
}

#[test]
fn a_namespace_is_validated_like_any_other_identifier() -> Result<()> {
    let host = ScriptedHost::silent();
    let store = Arc::new(MemoryStore::new());

    let named = DockerSandbox::with_namespace(host.clone(), store.clone(), "team-a")?;
    assert_eq!(named.namespace(), "team-a");
    assert_eq!(
        DockerSandbox::new(host.clone(), store.clone()).namespace(),
        "default"
    );

    // The namespace ends up in a container name, so it follows the same rule as
    // every other tinybox identifier.
    for bad in ["", "../escape", "has space", "a/b"] {
        assert!(
            matches!(
                DockerSandbox::with_namespace(host.clone(), store.clone(), bad),
                Err(Error::InvalidIdentifier {
                    kind: "docker namespace",
                    ..
                })
            ),
            "{bad:?} should be rejected as a namespace"
        );
    }
    Ok(())
}

#[tokio::test]
async fn containers_are_named_under_the_sandboxs_namespace() -> Result<()> {
    let host = ScriptedHost::silent();
    let sandbox =
        DockerSandbox::with_namespace(host.clone(), Arc::new(MemoryStore::new()), "team-a")?;

    sandbox.create(&spec()?).await?;

    let argv = host.command(0).unwrap_or_default();
    assert_eq!(flag_value(&argv, "--name"), Some("tinybox-team-a-box-0"));
    Ok(())
}

#[tokio::test]
async fn a_new_container_records_when_it_was_created() -> Result<()> {
    let clock = Arc::new(tinybox_core::clock::FixedClock::at_epoch());
    let sandbox = DockerSandbox::new(ScriptedHost::silent(), Arc::new(MemoryStore::new()))
        .with_clock(clock.clone());

    let first = sandbox.create(&spec()?).await?;
    clock.advance(std::time::Duration::from_secs(45));
    let second = sandbox.create(&spec()?).await?;

    assert_eq!(first.created_at, Some(std::time::SystemTime::UNIX_EPOCH));
    assert_eq!(
        second.created_at,
        Some(std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(45))
    );
    Ok(())
}

#[tokio::test]
async fn a_detached_process_is_started_through_docker_exec() -> Result<()> {
    let (sandbox, host, _store) = sandbox();
    let info = sandbox.create(&spec()?).await?;
    host.push_ok("running"); // inspect

    let process = sandbox
        .spawn(&info.id, &ExecRequest::new(["openhuman-core", "serve"]))
        .await?;

    let argv = host.command(2).unwrap_or_default();
    assert_eq!(argv[0..2], ["docker", "exec"]);
    // No `--detach`: the wrapper's own `&` is what backgrounds the process,
    // which is also what makes the pid recoverable. `docker exec --detach`
    // hands back nothing a caller could name.
    assert!(!argv.contains(&"--detach".to_owned()), "{argv:?}");
    let line = argv.last().map(String::as_str).unwrap_or_default();
    assert!(line.contains("'openhuman-core' 'serve'"), "{line:?}");
    assert!(line.contains(process.as_str()), "{line:?}");
    Ok(())
}

#[tokio::test]
async fn the_detach_wrapper_carries_cwd_and_env_rather_than_docker_flags() -> Result<()> {
    // Both would work, but only one of them survives the shell that has to
    // background the command, so the wrapper owns them and `args::exec` sees a
    // request with neither.
    let (sandbox, host, _store) = sandbox();
    let info = sandbox.create(&spec()?).await?;
    host.push_ok("running"); // inspect

    sandbox
        .spawn(
            &info.id,
            &ExecRequest::new(["server"])
                .with_cwd("/srv/work")
                .with_env("PORT", "7788"),
        )
        .await?;

    let argv = host.command(2).unwrap_or_default();
    assert!(!argv.contains(&"--workdir".to_owned()), "{argv:?}");
    assert!(!argv.contains(&"--env".to_owned()), "{argv:?}");
    let line = argv.last().map(String::as_str).unwrap_or_default();
    assert!(line.contains("cd '/srv/work' &&"), "{line:?}");
    assert!(line.contains("env 'PORT=7788'"), "{line:?}");
    Ok(())
}

#[tokio::test]
async fn a_probe_answers_from_what_the_container_printed() -> Result<()> {
    let (sandbox, host, _store) = sandbox();
    let info = sandbox.create(&spec()?).await?;
    host.push_ok("running"); // inspect
    host.push_ok("running"); // the probe itself

    assert!(
        sandbox
            .is_running(&info.id, &tinybox_core::ProcessId::new("p1-0")?)
            .await?
    );

    host.push_ok("running"); // inspect
    host.push_ok("gone");
    assert!(
        !sandbox
            .is_running(&info.id, &tinybox_core::ProcessId::new("p1-0")?)
            .await?
    );
    Ok(())
}

#[tokio::test]
async fn a_failed_start_carries_the_containers_diagnostic() -> Result<()> {
    // Unlike `exec`, where a non-zero status is a result, a detached start that
    // fails means no process exists — so it is an error, not an empty success
    // the caller would later probe and find "gone" for no stated reason.
    let (sandbox, host, _store) = sandbox();
    let info = sandbox.create(&spec()?).await?;
    host.push_ok("running"); // inspect
    host.push_failure("/bin/sh: openhuman-core: not found");

    let outcome = sandbox
        .spawn(&info.id, &ExecRequest::new(["openhuman-core"]))
        .await;

    assert_eq!(
        outcome.err(),
        Some(Error::Backend {
            sandbox: NAME.to_owned(),
            operation: "start a detached process",
            message: "/bin/sh: openhuman-core: not found".to_owned(),
        })
    );
    Ok(())
}

#[test]
fn detach_is_declared_because_a_container_persists_between_commands() {
    let declared = DockerSandbox::declared_capabilities();

    assert!(declared.supports(Capability::Detach));
}

#[test]
fn preflight_reports_each_enforced_boundary_without_claiming_disk() {
    use tinybox_core::{Constraint, Enforcement};
    let (backend, _, _) = sandbox();
    let support = backend.constraint_support();
    assert_eq!(
        support.enforcement(Constraint::Filesystem),
        Enforcement::Enforced
    );
    assert_eq!(
        support.enforcement(Constraint::Network),
        Enforcement::Enforced
    );
    assert_eq!(support.enforcement(Constraint::Cpu), Enforcement::Enforced);
    assert_eq!(
        support.enforcement(Constraint::Memory),
        Enforcement::Enforced
    );
    assert_eq!(support.enforcement(Constraint::Pids), Enforcement::Enforced);
    assert_eq!(
        support.enforcement(Constraint::Disk),
        Enforcement::Unsupported
    );
    assert_eq!(
        support.enforcement(Constraint::Subprocess),
        Enforcement::Unsupported
    );
    assert!(
        backend
            .require(&[Constraint::Filesystem, Constraint::Network])
            .is_ok()
    );
    assert!(backend.require(&[Constraint::Disk]).is_err());
}

#[tokio::test]
async fn an_unenforceable_network_allowlist_is_refused_at_creation() -> Result<()> {
    let (sandbox, _host, _store) = sandbox();
    let policy = tinybox_core::NetworkPolicy::Allowlist(tinybox_core::EgressAllowlist::new(
        ["example.com"],
        [443],
    ));
    let result = sandbox.create(&spec()?.with_network(policy)).await;
    assert!(matches!(
        result,
        Err(Error::ConstraintNotEnforced {
            constraint: tinybox_core::Constraint::Network,
            enforcement: tinybox_core::Enforcement::Unsupported,
            ..
        })
    ));
    Ok(())
}
