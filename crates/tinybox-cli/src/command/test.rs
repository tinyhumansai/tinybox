//! Tests for argument parsing and command dispatch.
//!
//! Every case drives [`run`] with an explicit `--store` under a temporary
//! directory, so no test touches the caller's real box records and none of
//! them depend on each other's state.

use std::collections::VecDeque;
use std::io::{self, Write};
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use async_trait::async_trait;
use clap::CommandFactory;
use tempfile::TempDir;
use tinybox_core::{Error, ExecOutput, ExecRequest, Host, Result};

use super::{Cli, EXIT_TINYBOX_ERROR, exit_code, run, run_with_host, workspace};

/// A writer that refuses every write, standing in for a closed pipe.
///
/// `tinybox ls | head -1` closes stdout while tinybox is still writing, and the
/// result should be a reported error rather than a panic.
struct BrokenPipe;

impl Write for BrokenPipe {
    fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
        Err(io::Error::from(io::ErrorKind::BrokenPipe))
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::from(io::ErrorKind::BrokenPipe))
    }
}

/// Run with a store inside `dir` and a stdout that cannot be written to.
async fn invoke_with_broken_stdout(dir: &Path, args: &[&str]) -> u8 {
    let store = dir.join("boxes.json");
    let mut line = vec!["tinybox".to_owned(), "--store".to_owned()];
    line.push(store.display().to_string());
    line.extend(args.iter().map(|arg| (*arg).to_owned()));

    let mut err = Vec::new();
    run(line, &mut BrokenPipe, &mut err).await
}

/// What one invocation produced.
struct Invocation {
    code: u8,
    out: String,
    err: String,
}

fn temp_dir() -> Result<TempDir> {
    TempDir::new().map_err(|error| Error::io("tempdir", &error))
}

/// Run `tinybox` with a store inside `dir`, capturing both streams.
async fn invoke(dir: &Path, args: &[&str]) -> Invocation {
    let store = dir.join("boxes.json");
    let mut line = vec!["tinybox".to_owned(), "--store".to_owned()];
    line.push(store.display().to_string());
    line.extend(args.iter().map(|arg| (*arg).to_owned()));

    let mut out = Vec::new();
    let mut err = Vec::new();
    let code = run(line, &mut out, &mut err).await;

    Invocation {
        code,
        out: String::from_utf8_lossy(&out).into_owned(),
        err: String::from_utf8_lossy(&err).into_owned(),
    }
}

#[tokio::test]
async fn a_box_can_be_created_used_and_removed() -> Result<()> {
    let dir = temp_dir()?;

    let created = invoke(dir.path(), &["create", "--dir", "/tmp"]).await;
    assert_eq!(created.code, 0);
    assert_eq!(created.out.trim(), "box-0");

    let listed = invoke(dir.path(), &["ls"]).await;
    assert_eq!(listed.code, 0);
    assert!(listed.out.contains("box-0"));
    assert!(listed.out.contains("ready"));
    assert!(listed.out.contains("/tmp"));

    let removed = invoke(dir.path(), &["rm", "box-0"]).await;
    assert_eq!(removed.code, 0);

    assert!(invoke(dir.path(), &["ls"]).await.out.is_empty());
    Ok(())
}

#[tokio::test]
async fn creating_a_box_warns_that_it_is_not_isolated() -> Result<()> {
    let dir = temp_dir()?;

    let created = invoke(dir.path(), &["create", "--dir", "/tmp"]).await;

    // A reader who never runs `inspect` still has to be told what they made.
    assert!(created.err.contains("not isolated"));
    // The warning goes to stderr so that `create` remains pipeable.
    assert_eq!(created.out.trim(), "box-0");
    Ok(())
}

#[tokio::test]
async fn a_box_persists_between_invocations() -> Result<()> {
    let dir = temp_dir()?;
    invoke(dir.path(), &["create", "--dir", "/tmp"]).await;

    // This is the whole reason the store is a file: a separate `run` call is
    // standing in for a separate process.
    let executed = invoke(dir.path(), &["exec", "box-0", "echo", "hello"]).await;

    assert_eq!(executed.code, 0);
    assert_eq!(executed.out.trim(), "hello");
    Ok(())
}

#[tokio::test]
async fn a_command_runs_in_the_box_workspace() -> Result<()> {
    let dir = temp_dir()?;
    let workspace = temp_dir()?;
    invoke(
        dir.path(),
        &["create", "--dir", &workspace.path().display().to_string()],
    )
    .await;

    let executed = invoke(dir.path(), &["exec", "box-0", "pwd"]).await;

    assert_eq!(
        Path::new(executed.out.trim()).canonicalize().ok(),
        workspace.path().canonicalize().ok()
    );
    Ok(())
}

#[tokio::test]
async fn box_environment_reaches_the_command() -> Result<()> {
    let dir = temp_dir()?;
    invoke(
        dir.path(),
        &["create", "--dir", "/tmp", "--env", "GREETING=hi"],
    )
    .await;

    let executed = invoke(
        dir.path(),
        &["exec", "box-0", "sh", "-c", "printf %s \"$GREETING\""],
    )
    .await;

    assert_eq!(executed.out, "hi");
    Ok(())
}

#[tokio::test]
async fn a_failing_command_sets_the_exit_code_without_being_an_error() -> Result<()> {
    let dir = temp_dir()?;
    invoke(dir.path(), &["create", "--dir", "/tmp"]).await;

    let executed = invoke(dir.path(), &["exec", "box-0", "sh", "-c", "exit 7"]).await;

    // The command failed; tinybox did not. That distinction is what the
    // dedicated tinybox exit code exists to preserve.
    assert_eq!(executed.code, 7);
    assert!(!executed.err.contains("error:"));
    Ok(())
}

#[tokio::test]
async fn stderr_from_the_command_is_kept_separate() -> Result<()> {
    let dir = temp_dir()?;
    invoke(dir.path(), &["create", "--dir", "/tmp"]).await;

    let executed = invoke(
        dir.path(),
        &["exec", "box-0", "sh", "-c", "echo out; echo err >&2"],
    )
    .await;

    assert_eq!(executed.out.trim(), "out");
    assert_eq!(executed.err.trim(), "err");
    Ok(())
}

#[tokio::test]
async fn run_creates_uses_and_destroys_a_box_in_one_step() -> Result<()> {
    let dir = temp_dir()?;

    let executed = invoke(dir.path(), &["run", "--dir", "/tmp", "echo", "once"]).await;

    assert_eq!(executed.code, 0);
    assert_eq!(executed.out.trim(), "once");
    // Nothing is left behind.
    assert!(invoke(dir.path(), &["ls"]).await.out.is_empty());
    Ok(())
}

#[tokio::test]
async fn run_leaves_nothing_behind_when_the_command_fails() -> Result<()> {
    let dir = temp_dir()?;

    let executed = invoke(dir.path(), &["run", "--dir", "/tmp", "sh", "-c", "exit 3"]).await;

    assert_eq!(executed.code, 3);
    // A failing command must not leak a box; the cleanup is unconditional.
    assert!(invoke(dir.path(), &["ls"]).await.out.is_empty());
    Ok(())
}

#[tokio::test]
async fn run_reports_a_command_that_cannot_start_and_still_cleans_up() -> Result<()> {
    let dir = temp_dir()?;

    let executed = invoke(
        dir.path(),
        &["run", "--dir", "/tmp", "tinybox-no-such-program"],
    )
    .await;

    assert_eq!(executed.code, EXIT_TINYBOX_ERROR);
    assert!(executed.err.contains("error:"));
    assert!(invoke(dir.path(), &["ls"]).await.out.is_empty());
    Ok(())
}

#[tokio::test]
async fn inspect_says_plainly_that_the_box_is_unsafe() -> Result<()> {
    let dir = temp_dir()?;
    invoke(dir.path(), &["create", "--dir", "/tmp"]).await;

    let inspected = invoke(dir.path(), &["inspect", "box-0"]).await;

    assert_eq!(inspected.code, 0);
    assert!(inspected.out.contains("isolation:  none"));
    assert!(inspected.out.contains("UNSAFE"));
    assert!(inspected.out.contains("runner:     local / passthrough"));
    Ok(())
}

#[tokio::test]
async fn an_unknown_box_is_an_error_not_a_silent_success() -> Result<()> {
    let dir = temp_dir()?;

    for args in [
        vec!["exec", "box-9", "true"],
        vec!["inspect", "box-9"],
        vec!["rm", "box-9"],
    ] {
        let outcome = invoke(dir.path(), &args).await;
        assert_eq!(outcome.code, EXIT_TINYBOX_ERROR, "for {args:?}");
        assert!(outcome.err.contains("no box with id box-9"), "for {args:?}");
    }
    Ok(())
}

#[tokio::test]
async fn an_invalid_identifier_is_refused_before_it_reaches_the_store() -> Result<()> {
    let dir = temp_dir()?;

    let outcome = invoke(dir.path(), &["inspect", "../escape"]).await;

    assert_eq!(outcome.code, EXIT_TINYBOX_ERROR);
    assert!(outcome.err.contains("not a valid box id"));
    Ok(())
}

#[tokio::test]
async fn a_malformed_environment_entry_is_rejected() -> Result<()> {
    let dir = temp_dir()?;

    let outcome = invoke(
        dir.path(),
        &["create", "--dir", "/tmp", "--env", "NO_EQUALS"],
    )
    .await;

    assert_eq!(outcome.code, EXIT_TINYBOX_ERROR);
    assert!(outcome.err.contains("KEY=VALUE"));
    Ok(())
}

#[tokio::test]
async fn boxes_are_numbered_across_invocations() -> Result<()> {
    let dir = temp_dir()?;

    assert_eq!(
        invoke(dir.path(), &["create", "--dir", "/tmp"])
            .await
            .out
            .trim(),
        "box-0"
    );
    assert_eq!(
        invoke(dir.path(), &["create", "--dir", "/tmp"])
            .await
            .out
            .trim(),
        "box-1"
    );
    Ok(())
}

#[tokio::test]
async fn a_usage_error_reports_clap_s_exit_code() -> Result<()> {
    let dir = temp_dir()?;

    let outcome = invoke(dir.path(), &["not-a-command"]).await;

    assert_eq!(outcome.code, 2);
    assert!(!outcome.err.is_empty());
    Ok(())
}

#[tokio::test]
async fn exec_without_a_command_is_a_usage_error() -> Result<()> {
    let dir = temp_dir()?;

    let outcome = invoke(dir.path(), &["exec", "box-0"]).await;

    assert_eq!(outcome.code, 2);
    Ok(())
}

#[tokio::test]
async fn requested_help_goes_to_stdout_and_usage_errors_to_stderr() -> Result<()> {
    let dir = temp_dir()?;

    for flag in ["--help", "--version"] {
        let outcome = invoke(dir.path(), &[flag]).await;
        assert_eq!(outcome.code, 0, "for {flag}");
        // Asked-for output belongs on stdout, or `tinybox --help | less` comes
        // back empty.
        assert!(!outcome.out.is_empty(), "for {flag}");
        assert!(outcome.err.is_empty(), "for {flag}");
    }

    // A mistake is a diagnostic, and stays on stderr.
    let misuse = invoke(dir.path(), &["not-a-command"]).await;
    assert_eq!(misuse.code, 2);
    assert!(misuse.out.is_empty());
    assert!(!misuse.err.is_empty());
    Ok(())
}

#[test]
fn the_command_surface_is_internally_consistent() {
    // clap's own assertions catch conflicting flags, duplicate names, and
    // missing help text, and they only run when something asks for them.
    Cli::command().debug_assert();
}

#[test]
fn an_exit_status_outside_a_byte_becomes_the_tinybox_error_code() {
    assert_eq!(exit_code(0), 0);
    assert_eq!(exit_code(7), 7);
    assert_eq!(exit_code(255), 255);
    // Reporting 0 for an unrepresentable status would turn a failure into a
    // success, so it maps to the tinybox error code instead.
    assert_eq!(exit_code(256), EXIT_TINYBOX_ERROR);
    assert_eq!(exit_code(-1), EXIT_TINYBOX_ERROR);
}

#[tokio::test]
async fn a_corrupt_store_is_reported_rather_than_ignored() -> Result<()> {
    let dir = temp_dir()?;
    std::fs::write(dir.path().join("boxes.json"), "{ not json")
        .map_err(|error| Error::io("write", &error))?;

    let outcome = invoke(dir.path(), &["ls"]).await;

    assert_eq!(outcome.code, EXIT_TINYBOX_ERROR);
    assert!(outcome.err.contains("not a valid box store"));
    Ok(())
}

#[tokio::test]
async fn a_closed_output_stream_is_reported_rather_than_panicking() -> Result<()> {
    let dir = temp_dir()?;
    // Seed a box so the read-only commands have something to print.
    invoke(dir.path(), &["create", "--dir", "/tmp"]).await;

    for args in [
        vec!["create", "--dir", "/tmp"],
        vec!["ls"],
        vec!["inspect", "box-0"],
        vec!["rm", "box-0"],
        vec!["exec", "box-0", "echo", "hi"],
        vec!["run", "--dir", "/tmp", "echo", "hi"],
    ] {
        let code = invoke_with_broken_stdout(dir.path(), &args).await;
        assert_eq!(code, EXIT_TINYBOX_ERROR, "for {args:?}");
    }
    Ok(())
}

#[tokio::test]
async fn a_closed_error_stream_is_survivable_too() -> Result<()> {
    let dir = temp_dir()?;
    let store = dir.path().join("boxes.json");

    // `create` writes its isolation warning to stderr; a closed stderr must not
    // take the process down.
    let line = vec![
        "tinybox".to_owned(),
        "--store".to_owned(),
        store.display().to_string(),
        "create".to_owned(),
        "--dir".to_owned(),
        "/tmp".to_owned(),
    ];
    let mut out = Vec::new();
    let code = run(line, &mut out, &mut BrokenPipe).await;

    assert_eq!(code, EXIT_TINYBOX_ERROR);
    Ok(())
}

#[test]
fn every_workspace_source_renders_readably() -> Result<()> {
    use tinybox_core::{
        BoxId, BoxInfo, BoxSpec, BoxState, HostRef, Placement, SandboxRef, SnapshotId,
        WorkspaceSource,
    };

    let render = |source| -> Result<String> {
        let spec = BoxSpec::new(
            Placement::new(HostRef::new("local")?, SandboxRef::new("docker")?),
            source,
        );
        Ok(workspace(&BoxInfo::new(
            BoxId::new("box-0")?,
            BoxState::Ready,
            spec,
        )))
    };

    // This is the column someone scans to find the box they meant, so each
    // variant gets a form they recognize rather than a Debug dump.
    assert_eq!(
        render(WorkspaceSource::LocalDir("/srv/work".into()))?,
        "/srv/work"
    );
    assert_eq!(
        render(WorkspaceSource::OciImage("alpine:3".to_owned()))?,
        "alpine:3"
    );
    assert_eq!(
        render(WorkspaceSource::Snapshot(SnapshotId::new("sha-abc123")?))?,
        "sha-abc123"
    );
    assert_eq!(
        render(WorkspaceSource::GitRepo {
            url: "https://example.invalid/repo.git".to_owned(),
            rev: "main".to_owned(),
        })?,
        "https://example.invalid/repo.git#main"
    );
    Ok(())
}

#[tokio::test]
async fn a_boxs_sandbox_is_read_from_its_record_not_a_flag() -> Result<()> {
    let dir = temp_dir()?;
    invoke(dir.path(), &["create", "--dir", "/tmp"]).await;

    // No `--sandbox` here, and none is needed: asking the caller to remember
    // which backend a box belongs to is how containers get orphaned.
    let listed = invoke(dir.path(), &["ls"]).await;
    assert!(listed.out.contains("passthrough"));

    let inspected = invoke(dir.path(), &["inspect", "box-0"]).await;
    assert!(inspected.out.contains("sandbox:    passthrough"));
    Ok(())
}

#[tokio::test]
async fn a_record_naming_an_unknown_sandbox_is_refused() -> Result<()> {
    let dir = temp_dir()?;
    // A store written by a newer build, naming a backend this one lacks.
    std::fs::write(
        dir.path().join("boxes.json"),
        r#"{"box-0":{"id":"box-0","state":"Ready","spec":{
            "runner":{"host":"local","sandbox":"microvm"},
            "workspace":{"host":"local","sandbox":"microvm"},
            "source":{"LocalDir":"/tmp"},
            "resources":{"cpu_millis":2000,"memory_bytes":2147483648,"pids_max":512,"disk_bytes":8589934592},
            "lifecycle":{"Ephemeral":{"ttl":{"secs":3600,"nanos":0}}},
            "network":"Denied","env":{}}}}"#,
    )
    .map_err(|error| Error::io("write", &error))?;

    let outcome = invoke(dir.path(), &["inspect", "box-0"]).await;

    assert_eq!(outcome.code, EXIT_TINYBOX_ERROR);
    assert!(outcome.err.contains("microvm"));
    Ok(())
}

#[tokio::test]
async fn inspect_lists_what_the_sandbox_declares() -> Result<()> {
    let dir = temp_dir()?;
    invoke(dir.path(), &["create", "--dir", "/tmp"]).await;

    let inspected = invoke(dir.path(), &["inspect", "box-0"]).await;

    // Passthrough declares nothing, and says that rather than printing an
    // empty list the reader has to interpret.
    assert!(
        inspected
            .out
            .contains("supports:   nothing beyond running commands")
    );
    Ok(())
}

#[tokio::test]
async fn an_image_and_a_directory_are_alternatives() -> Result<()> {
    let dir = temp_dir()?;

    let outcome = invoke(
        dir.path(),
        &[
            "create",
            "--sandbox",
            "docker",
            "--image",
            "alpine:3",
            "--dir",
            "/tmp",
        ],
    )
    .await;

    // An image *is* the filesystem; a directory is mounted into one. Accepting
    // both would leave it ambiguous which won.
    assert_eq!(outcome.code, 2);
    Ok(())
}

#[tokio::test]
async fn an_invalid_docker_namespace_is_refused() -> Result<()> {
    let dir = temp_dir()?;

    let outcome = invoke(
        dir.path(),
        &[
            "--namespace",
            "../escape",
            "create",
            "--sandbox",
            "docker",
            "--image",
            "alpine:3",
        ],
    )
    .await;

    assert_eq!(outcome.code, EXIT_TINYBOX_ERROR);
    assert!(outcome.err.contains("docker namespace"));
    Ok(())
}

#[tokio::test]
async fn snapshotting_a_passthrough_box_is_refused_rather_than_faked() -> Result<()> {
    let dir = temp_dir()?;
    invoke(dir.path(), &["create", "--dir", "/tmp"]).await;

    let outcome = invoke(dir.path(), &["snapshot", "box-0"]).await;

    assert_eq!(outcome.code, EXIT_TINYBOX_ERROR);
    assert!(
        outcome
            .err
            .contains("does not support filesystem snapshots")
    );
    Ok(())
}

/// A host that answers `docker` commands from a queue.
///
/// The CLI's Docker paths are otherwise unreachable without a daemon, and the
/// argv decisions they make are exactly the part worth pinning.
#[derive(Debug, Default)]
struct ScriptedHost {
    replies: Mutex<VecDeque<ExecOutput>>,
    seen: Mutex<Vec<Vec<String>>>,
}

impl ScriptedHost {
    fn replies(&self) -> MutexGuard<'_, VecDeque<ExecOutput>> {
        self.replies.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn seen(&self) -> MutexGuard<'_, Vec<Vec<String>>> {
        self.seen.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn push_ok(&self, stdout: &str) {
        self.replies()
            .push_back(ExecOutput::new(0, stdout.as_bytes().to_vec(), Vec::new()));
    }

    fn commands(&self) -> Vec<Vec<String>> {
        self.seen().clone()
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

/// Run `tinybox` against a scripted host rather than the real machine.
async fn invoke_scripted(dir: &Path, host: Arc<ScriptedHost>, args: &[&str]) -> Invocation {
    let store = dir.join("boxes.json");
    let mut line = vec!["tinybox".to_owned(), "--store".to_owned()];
    line.push(store.display().to_string());
    line.extend(args.iter().map(|arg| (*arg).to_owned()));

    let mut out = Vec::new();
    let mut err = Vec::new();
    let code = run_with_host(line, host, &mut out, &mut err).await;

    Invocation {
        code,
        out: String::from_utf8_lossy(&out).into_owned(),
        err: String::from_utf8_lossy(&err).into_owned(),
    }
}

#[tokio::test]
async fn a_docker_box_is_created_through_the_docker_backend() -> Result<()> {
    let dir = temp_dir()?;
    let host = Arc::new(ScriptedHost::default());

    let created = invoke_scripted(
        dir.path(),
        host.clone(),
        &["create", "--sandbox", "docker", "--image", "alpine:3"],
    )
    .await;

    assert_eq!(created.code, 0);
    assert_eq!(created.out.trim(), "box-0");
    // Docker clears the isolation floor, so no "not isolated" warning is due.
    assert!(!created.err.contains("not isolated"));

    let argv = host.commands().first().cloned().unwrap_or_default();
    assert_eq!(argv[0..2], ["docker", "run"]);
    assert!(argv.contains(&"alpine:3".to_owned()));
    Ok(())
}

#[tokio::test]
async fn a_docker_box_remembers_its_backend_across_invocations() -> Result<()> {
    let dir = temp_dir()?;
    let host = Arc::new(ScriptedHost::default());
    invoke_scripted(
        dir.path(),
        host.clone(),
        &["create", "--sandbox", "docker", "--image", "alpine:3"],
    )
    .await;

    host.push_ok("running"); // inspect, during exec
    host.push_ok("hi"); // the command itself
    let executed =
        invoke_scripted(dir.path(), host.clone(), &["exec", "box-0", "echo", "hi"]).await;

    // No `--sandbox` was given: the record said docker, so docker was used.
    assert_eq!(executed.code, 0);
    let last = host.commands().last().cloned().unwrap_or_default();
    assert_eq!(last[0..2], ["docker", "exec"]);
    Ok(())
}

#[tokio::test]
async fn a_docker_box_can_be_snapshotted_and_forked() -> Result<()> {
    let dir = temp_dir()?;
    let host = Arc::new(ScriptedHost::default());
    invoke_scripted(
        dir.path(),
        host.clone(),
        &["create", "--sandbox", "docker", "--image", "alpine:3"],
    )
    .await;

    host.push_ok("sha256:9f2c0e1b7a4d5e6f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f");
    let captured = invoke_scripted(dir.path(), host.clone(), &["snapshot", "box-0"]).await;
    assert_eq!(captured.code, 0);
    assert_eq!(captured.out.trim(), "sha-9f2c0e1b7a4d");

    let forked = invoke_scripted(
        dir.path(),
        host.clone(),
        &["fork", captured.out.trim(), "--sandbox", "docker"],
    )
    .await;
    assert_eq!(forked.code, 0);
    assert_eq!(forked.out.trim(), "box-1");

    // The fork starts from the snapshot image, not the original spec's.
    let last = host.commands().last().cloned().unwrap_or_default();
    assert!(last.contains(&"9f2c0e1b7a4d".to_owned()));
    Ok(())
}

#[tokio::test]
async fn a_docker_box_is_destroyed_through_docker() -> Result<()> {
    let dir = temp_dir()?;
    let host = Arc::new(ScriptedHost::default());
    invoke_scripted(
        dir.path(),
        host.clone(),
        &["create", "--sandbox", "docker", "--image", "alpine:3"],
    )
    .await;

    let removed = invoke_scripted(dir.path(), host.clone(), &["rm", "box-0"]).await;

    assert_eq!(removed.code, 0);
    let last = host.commands().last().cloned().unwrap_or_default();
    assert_eq!(last[0..2], ["docker", "rm"]);
    Ok(())
}

#[tokio::test]
async fn inspecting_a_docker_box_reports_kernel_isolation() -> Result<()> {
    let dir = temp_dir()?;
    let host = Arc::new(ScriptedHost::default());
    invoke_scripted(
        dir.path(),
        host.clone(),
        &["create", "--sandbox", "docker", "--image", "alpine:3"],
    )
    .await;
    host.push_ok("running");

    let inspected = invoke_scripted(dir.path(), host.clone(), &["inspect", "box-0"]).await;

    assert!(inspected.out.contains("sandbox:    docker"));
    assert!(inspected.out.contains("isolation:  kernel"));
    assert!(inspected.out.contains("untrusted:  safe"));
    assert!(
        inspected
            .out
            .contains("filesystem snapshots, forking, resource limits")
    );
    // The workspace column shows the image, not a Debug dump.
    assert!(inspected.out.contains("workspace:  alpine:3"));
    Ok(())
}

#[tokio::test]
async fn a_namespace_reaches_the_container_name() -> Result<()> {
    let dir = temp_dir()?;
    let host = Arc::new(ScriptedHost::default());

    invoke_scripted(
        dir.path(),
        host.clone(),
        &[
            "--namespace",
            "team-a",
            "create",
            "--sandbox",
            "docker",
            "--image",
            "alpine:3",
        ],
    )
    .await;

    let argv = host.commands().first().cloned().unwrap_or_default();
    let name = argv
        .iter()
        .position(|part| part == "--name")
        .and_then(|index| argv.get(index + 1));
    assert_eq!(name.map(String::as_str), Some("tinybox-team-a-box-0"));
    Ok(())
}

#[tokio::test]
async fn a_one_shot_docker_run_leaves_nothing_behind() -> Result<()> {
    let dir = temp_dir()?;
    let host = Arc::new(ScriptedHost::default());
    host.push_ok(""); // docker run
    host.push_ok("running"); // inspect
    host.push_ok("once"); // the command

    let executed = invoke_scripted(
        dir.path(),
        host.clone(),
        &[
            "run",
            "--sandbox",
            "docker",
            "--image",
            "alpine:3",
            "echo",
            "once",
        ],
    )
    .await;

    assert_eq!(executed.code, 0);
    assert_eq!(executed.out.trim(), "once");
    assert!(
        invoke_scripted(dir.path(), host.clone(), &["ls"])
            .await
            .out
            .is_empty()
    );
    Ok(())
}
