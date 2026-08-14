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
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use async_trait::async_trait;
use tinybox_core::{
    BoxId, BoxSpec, BoxState, Capability, Error, ExecOutput, ExecRequest, Host, HostRef,
    IsolationLevel, MemoryStore, NetworkPolicy, Placement, PortMapping, Resources, Result, Sandbox,
    SandboxRef, SnapshotId, SnapshotSupport, Store, WorkspaceSource,
};

use super::{DockerSandbox, NAME, args, state};

/// A digest `docker commit` might print.
const COMMIT_OUTPUT: &str =
    "sha256:9f2c0e1b7a4d5e6f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f";

/// A host that replays scripted replies and records what it was asked to run.
#[derive(Debug, Default)]
struct ScriptedHost {
    replies: Mutex<VecDeque<ExecOutput>>,
    seen: Mutex<Vec<Vec<String>>>,
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
        Ok(self
            .replies()
            .pop_front()
            .unwrap_or_else(|| ExecOutput::new(0, Vec::new(), Vec::new())))
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

#[test]
fn it_declares_kernel_isolation_and_filesystem_snapshots() {
    let caps = DockerSandbox::declared_capabilities();

    assert_eq!(caps.isolation, IsolationLevel::Kernel);
    assert_eq!(caps.snapshot, SnapshotSupport::Filesystem);
    // The first backend that is a defensible place for untrusted code.
    assert!(caps.is_suitable_for_untrusted_code());
    assert!(caps.supports(Capability::Fork));
    assert!(caps.supports(Capability::ResourceLimits));
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
    assert!(host.commands().is_empty(), "nothing should have been run");
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
    assert!(store.list()?.is_empty());
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
    assert!(store.list()?.is_empty());
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
    assert!(host.commands().is_empty());
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
    assert!(host.commands().is_empty());
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
