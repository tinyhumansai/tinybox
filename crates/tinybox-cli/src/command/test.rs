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
async fn a_store_written_before_ports_existed_still_loads() -> Result<()> {
    let dir = temp_dir()?;
    // Exactly the JSON an M3 build wrote: no `ports` field at all. Failing to
    // read it would orphan every box a user already had.
    std::fs::write(
        dir.path().join("boxes.json"),
        r#"{"box-0":{"id":"box-0","state":"Ready","spec":{
            "runner":{"host":"local","sandbox":"passthrough"},
            "workspace":{"host":"local","sandbox":"passthrough"},
            "source":{"LocalDir":"/tmp"},
            "resources":{"cpu_millis":2000,"memory_bytes":2147483648,"pids_max":512,"disk_bytes":8589934592},
            "lifecycle":{"Ephemeral":{"ttl":{"secs":3600,"nanos":0}}},
            "network":"Denied","env":{}}}}"#,
    )
    .map_err(|error| Error::io("write", &error))?;

    let listed = invoke(dir.path(), &["ls"]).await;

    assert_eq!(listed.code, 0);
    assert!(listed.out.contains("box-0"));
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

    // Passthrough declares detached processes and nothing else: a box here is
    // an ordinary directory on this machine, so a backgrounded process really
    // does survive between commands, but there is no filesystem boundary to
    // snapshot and no limit it can apply.
    assert!(
        inspected.out.contains("supports:   detached processes"),
        "{}",
        inspected.out
    );
    assert!(!inspected.out.contains("filesystem snapshots"));
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
            .contains("filesystem snapshots, forking, port forwarding, resource limits")
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

#[tokio::test]
async fn a_remote_host_makes_every_command_cross_the_connection() -> Result<()> {
    let dir = temp_dir()?;
    let host = Arc::new(ScriptedHost::default());

    invoke_scripted(
        dir.path(),
        host.clone(),
        &[
            "--host",
            "ssh://builder@example.invalid",
            "create",
            "--sandbox",
            "docker",
            "--image",
            "alpine:3",
        ],
    )
    .await;

    // The local machine ran `ssh`; the far machine ran `docker`. No CLI code
    // knows what that pairing is called.
    let argv = host.commands().first().cloned().unwrap_or_default();
    assert_eq!(argv.first().map(String::as_str), Some("ssh"));
    assert!(argv.contains(&"builder@example.invalid".to_owned()));
    assert!(
        argv.last()
            .is_some_and(|remote| remote.starts_with("'docker' 'run'"))
    );
    Ok(())
}

#[tokio::test]
async fn a_remote_box_records_where_it_actually_runs() -> Result<()> {
    let dir = temp_dir()?;
    let host = Arc::new(ScriptedHost::default());
    invoke_scripted(
        dir.path(),
        host.clone(),
        &[
            "--host",
            "builder",
            "create",
            "--sandbox",
            "docker",
            "--image",
            "alpine:3",
        ],
    )
    .await;

    host.push_ok("running");
    let inspected = invoke_scripted(dir.path(), host.clone(), &["inspect", "box-0"]).await;

    // Recording "local" here would make `inspect` lie about where the box is.
    assert!(inspected.out.contains("runner:     ssh / docker"));
    Ok(())
}

#[tokio::test]
async fn an_ssh_destination_that_would_be_read_as_an_option_is_refused() -> Result<()> {
    let dir = temp_dir()?;
    let host = Arc::new(ScriptedHost::default());

    // `--host=` rather than `--host ` so clap does not reject it as a stray
    // option first; the point is that tinybox refuses it too.
    let outcome = invoke_scripted(
        dir.path(),
        host.clone(),
        &["--host=-oProxyCommand=touch /tmp/pwned", "ls"],
    )
    .await;

    assert_eq!(outcome.code, EXIT_TINYBOX_ERROR);
    assert!(outcome.err.contains("ssh destination"));
    assert!(host.commands().is_empty());
    Ok(())
}

#[tokio::test]
async fn published_ports_reach_the_backend_and_open_the_network() -> Result<()> {
    let dir = temp_dir()?;
    let host = Arc::new(ScriptedHost::default());

    invoke_scripted(
        dir.path(),
        host.clone(),
        &[
            "create",
            "--sandbox",
            "docker",
            "--image",
            "alpine:3",
            "-p",
            "8080",
            "-p",
            "18080:80",
        ],
    )
    .await;

    let argv = host.commands().first().cloned().unwrap_or_default();
    // Publishing implies a network; leaving the default denial in place would
    // make `--publish` silently do nothing.
    assert!(!argv.contains(&"none".to_owned()), "{argv:?}");

    let published = argv
        .iter()
        .enumerate()
        .filter(|(_, part)| part.as_str() == "--publish")
        .filter_map(|(index, _)| argv.get(index + 1).cloned())
        .collect::<Vec<_>>();
    // Ordered by guest port, because the spec holds them in a set.
    assert_eq!(published, ["18080:80", "8080"]);
    Ok(())
}

#[tokio::test]
async fn a_malformed_port_is_rejected_with_the_expected_form() -> Result<()> {
    let dir = temp_dir()?;

    for bad in ["notaport", "70000", "80:", ":80", "a:b"] {
        let outcome = invoke(
            dir.path(),
            &[
                "create",
                "--sandbox",
                "docker",
                "--image",
                "alpine:3",
                "-p",
                bad,
            ],
        )
        .await;
        assert_eq!(outcome.code, EXIT_TINYBOX_ERROR, "for {bad:?}");
        assert!(outcome.err.contains("GUEST or HOST:GUEST"), "for {bad:?}");
    }
    Ok(())
}

#[tokio::test]
async fn syncing_reports_what_it_did_and_skips_an_unchanged_tree() -> Result<()> {
    let state = temp_dir()?;
    let source = temp_dir()?;
    let destination = temp_dir()?;
    std::fs::write(source.path().join("a.txt"), "alpha")
        .map_err(|error| Error::io("write", &error))?;

    let target = destination.path().join("work").display().to_string();
    let args = [
        "sync",
        "--dir",
        &source.path().display().to_string(),
        "--to",
        &target,
    ];

    let first = invoke(state.path(), &args).await;
    assert_eq!(first.code, 0);
    assert!(first.out.starts_with("sent\t"), "{}", first.out);

    let second = invoke(state.path(), &args).await;
    assert!(second.out.starts_with("unchanged\t"), "{}", second.out);
    // The same fingerprint both times, so the report is checkable.
    assert_eq!(
        first.out.split('\t').nth(1),
        second.out.trim_end().split('\t').nth(1)
    );
    Ok(())
}

#[tokio::test]
async fn syncing_honours_the_workspaces_own_ignore_rules() -> Result<()> {
    let state = temp_dir()?;
    let source = temp_dir()?;
    let destination = temp_dir()?;
    std::fs::write(source.path().join("a.txt"), "alpha")
        .map_err(|error| Error::io("write", &error))?;
    // Nobody names these on the command line: the project already said so.
    std::fs::write(source.path().join(".gitignore"), "target/\n")
        .map_err(|error| Error::io("write", &error))?;
    std::fs::create_dir(source.path().join("target"))
        .map_err(|error| Error::io("mkdir", &error))?;
    std::fs::write(source.path().join("target/huge"), "artifact")
        .map_err(|error| Error::io("write", &error))?;

    let target = destination.path().join("work").display().to_string();
    let args = [
        "sync",
        "--dir",
        &source.path().display().to_string(),
        "--to",
        &target,
    ];
    let outcome = invoke(state.path(), &args).await;

    assert_eq!(outcome.code, 0, "{}", outcome.err);
    assert!(Path::new(&target).join("a.txt").exists());
    assert!(!Path::new(&target).join("target").exists());
    Ok(())
}

#[tokio::test]
async fn syncing_can_be_told_to_send_everything() -> Result<()> {
    let state = temp_dir()?;
    let source = temp_dir()?;
    let destination = temp_dir()?;
    std::fs::write(source.path().join(".gitignore"), "keep-out/\n")
        .map_err(|error| Error::io("write", &error))?;
    std::fs::create_dir(source.path().join("keep-out"))
        .map_err(|error| Error::io("mkdir", &error))?;
    std::fs::write(source.path().join("keep-out/file"), "data")
        .map_err(|error| Error::io("write", &error))?;

    let target = destination.path().join("work").display().to_string();
    invoke(
        state.path(),
        &[
            "sync",
            "--dir",
            &source.path().display().to_string(),
            "--to",
            &target,
            "--no-ignore",
        ],
    )
    .await;

    // Overriding the project's own rules has to be explicit, and it has to work.
    assert!(Path::new(&target).join("keep-out/file").exists());
    Ok(())
}

#[tokio::test]
async fn a_box_can_be_saved_as_a_template_and_started_from() -> Result<()> {
    let dir = temp_dir()?;
    let host = Arc::new(ScriptedHost::default());
    invoke_scripted(
        dir.path(),
        host.clone(),
        &["create", "--sandbox", "docker", "--image", "alpine:3"],
    )
    .await;

    host.push_ok("sha256:9f2c0e1b7a4d5e6f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f");
    let saved = invoke_scripted(
        dir.path(),
        host.clone(),
        &["template", "save", "rust-ci", "--from", "box-0"],
    )
    .await;
    assert_eq!(saved.code, 0, "{}", saved.err);
    assert!(saved.out.contains("rust-ci"));
    assert!(saved.out.contains("sha-9f2c0e1b7a4d"));

    // Starting from the name rather than the digest is the whole point: the
    // digest is not something anyone should have to keep track of.
    let created = invoke_scripted(
        dir.path(),
        host.clone(),
        &["create", "--sandbox", "docker", "--template", "rust-ci"],
    )
    .await;
    assert_eq!(created.code, 0, "{}", created.err);

    let argv = host.commands().last().cloned().unwrap_or_default();
    assert!(argv.contains(&"9f2c0e1b7a4d".to_owned()), "{argv:?}");
    Ok(())
}

#[tokio::test]
async fn templates_can_be_listed_and_forgotten() -> Result<()> {
    let dir = temp_dir()?;
    let host = Arc::new(ScriptedHost::default());
    invoke_scripted(
        dir.path(),
        host.clone(),
        &["create", "--sandbox", "docker", "--image", "alpine:3"],
    )
    .await;
    host.push_ok("sha256:9f2c0e1b7a4d5e6f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f");
    invoke_scripted(
        dir.path(),
        host.clone(),
        &["template", "save", "ci", "--from", "box-0"],
    )
    .await;

    let listed = invoke(dir.path(), &["template", "ls"]).await;
    assert!(listed.out.contains("ci"));
    assert!(listed.out.contains("sha-9f2c0e1b7a4d"));

    assert_eq!(invoke(dir.path(), &["template", "rm", "ci"]).await.code, 0);
    assert!(invoke(dir.path(), &["template", "ls"]).await.out.is_empty());
    Ok(())
}

#[tokio::test]
async fn starting_from_an_unsaved_template_is_refused() -> Result<()> {
    let dir = temp_dir()?;

    let outcome = invoke(
        dir.path(),
        &["create", "--sandbox", "docker", "--template", "never-saved"],
    )
    .await;

    assert_eq!(outcome.code, EXIT_TINYBOX_ERROR);
    assert!(outcome.err.contains("no template named never-saved"));
    Ok(())
}

#[tokio::test]
async fn a_template_lives_beside_the_boxes_it_came_from() -> Result<()> {
    let dir = temp_dir()?;
    let host = Arc::new(ScriptedHost::default());
    invoke_scripted(
        dir.path(),
        host.clone(),
        &["create", "--sandbox", "docker", "--image", "alpine:3"],
    )
    .await;
    host.push_ok("sha256:9f2c0e1b7a4d5e6f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f");
    invoke_scripted(
        dir.path(),
        host.clone(),
        &["template", "save", "ci", "--from", "box-0"],
    )
    .await;

    // A separate file, so adding templates could not break a store written
    // before they existed.
    assert!(dir.path().join("templates.json").exists());
    assert!(dir.path().join("boxes.json").exists());
    Ok(())
}

#[tokio::test]
async fn a_template_and_an_image_are_alternatives() -> Result<()> {
    let dir = temp_dir()?;

    let outcome = invoke(
        dir.path(),
        &[
            "create",
            "--sandbox",
            "docker",
            "--template",
            "ci",
            "--image",
            "alpine:3",
        ],
    )
    .await;

    // Three answers to the same question; accepting two would leave it
    // ambiguous which won.
    assert_eq!(outcome.code, 2);
    Ok(())
}

#[tokio::test]
async fn reaping_destroys_only_what_has_expired() -> Result<()> {
    let dir = temp_dir()?;
    // A box created long ago with the default one-hour ttl, and one created now.
    let old = std::time::SystemTime::UNIX_EPOCH;
    let recent = std::time::SystemTime::now();
    write_boxes(dir.path(), &[("box-0", Some(old)), ("box-1", Some(recent))])?;

    let reaped = invoke(dir.path(), &["reap"]).await;

    assert_eq!(reaped.code, 0, "{}", reaped.err);
    assert!(reaped.out.contains("reaped\tbox-0"), "{}", reaped.out);
    assert!(!reaped.out.contains("box-1"), "{}", reaped.out);

    let listed = invoke(dir.path(), &["ls"]).await;
    assert!(!listed.out.contains("box-0"));
    assert!(listed.out.contains("box-1"));
    Ok(())
}

#[tokio::test]
async fn a_dry_run_reaps_nothing() -> Result<()> {
    let dir = temp_dir()?;
    write_boxes(
        dir.path(),
        &[("box-0", Some(std::time::SystemTime::UNIX_EPOCH))],
    )?;

    let reaped = invoke(dir.path(), &["reap", "--dry-run"]).await;

    assert!(reaped.out.contains("would reap\tbox-0"), "{}", reaped.out);
    // Still there.
    assert!(invoke(dir.path(), &["ls"]).await.out.contains("box-0"));
    Ok(())
}

#[tokio::test]
async fn a_box_with_no_recorded_creation_time_is_never_reaped() -> Result<()> {
    let dir = temp_dir()?;
    // What a store written before tinybox tracked time contains.
    write_boxes(dir.path(), &[("box-0", None)])?;

    let reaped = invoke(dir.path(), &["reap"]).await;

    assert!(reaped.out.is_empty(), "{}", reaped.out);
    assert!(invoke(dir.path(), &["ls"]).await.out.contains("box-0"));
    Ok(())
}

/// Write a box store containing the given boxes and creation times.
///
/// Written as JSON rather than created through the CLI, because the point is to
/// control the timestamps exactly — including the case where there is none.
fn write_boxes(dir: &Path, boxes: &[(&str, Option<std::time::SystemTime>)]) -> Result<()> {
    let mut records = Vec::new();
    for (id, created) in boxes {
        let created = match created {
            Some(at) => {
                let since = at
                    .duration_since(std::time::SystemTime::UNIX_EPOCH)
                    .unwrap_or_default();
                format!(
                    r#","created_at":{{"secs_since_epoch":{},"nanos_since_epoch":{}}}"#,
                    since.as_secs(),
                    since.subsec_nanos()
                )
            }
            None => String::new(),
        };
        records.push(format!(
            r#""{id}":{{"id":"{id}","state":"Ready","spec":{{
                "runner":{{"host":"local","sandbox":"passthrough"}},
                "workspace":{{"host":"local","sandbox":"passthrough"}},
                "source":{{"LocalDir":"/tmp"}},
                "resources":{{"cpu_millis":2000,"memory_bytes":2147483648,"pids_max":512,"disk_bytes":8589934592}},
                "lifecycle":{{"Ephemeral":{{"ttl":{{"secs":3600,"nanos":0}}}}}},
                "network":"Denied","ports":[],"env":{{}}}}{created}}}"#
        ));
    }
    std::fs::write(dir.join("boxes.json"), format!("{{{}}}", records.join(",")))
        .map_err(|error| Error::io("write", &error))
}

#[tokio::test]
async fn a_spawned_process_outlives_the_command_that_started_it() -> Result<()> {
    // The whole point of `spawn` over `exec`: a separate invocation is standing
    // in for a separate process, and the thing started by the first one is
    // still there for the second to ask about.
    let dir = temp_dir()?;
    invoke(dir.path(), &["create", "--dir", "/tmp"]).await;

    let spawned = invoke(dir.path(), &["spawn", "box-0", "sleep", "30"]).await;
    assert_eq!(spawned.code, 0);
    let process = spawned.out.trim().to_owned();
    assert!(!process.is_empty(), "spawn prints an identifier");

    let running = invoke(dir.path(), &["ps", "box-0", &process]).await;
    assert_eq!(running.out.trim(), "running");

    let killed = invoke(dir.path(), &["kill", "box-0", &process]).await;
    assert_eq!(killed.code, 0);

    let gone = invoke(dir.path(), &["ps", "box-0", &process]).await;
    // `gone` on stdout with a zero exit: the process finishing is an answer,
    // not a failure, and reporting it as one would be indistinguishable from
    // an unreachable box.
    assert_eq!(gone.code, 0);
    assert_eq!(gone.out.trim(), "gone");
    Ok(())
}

#[tokio::test]
async fn asking_about_a_process_that_was_never_started_answers_gone() -> Result<()> {
    let dir = temp_dir()?;
    invoke(dir.path(), &["create", "--dir", "/tmp"]).await;

    let answer = invoke(dir.path(), &["ps", "box-0", "p1-0"]).await;

    assert_eq!(answer.code, 0);
    assert_eq!(answer.out.trim(), "gone");
    Ok(())
}

#[tokio::test]
async fn killing_a_process_that_has_already_exited_is_not_an_error() -> Result<()> {
    // Stopping something already stopped is the outcome the caller wanted.
    let dir = temp_dir()?;
    invoke(dir.path(), &["create", "--dir", "/tmp"]).await;

    let killed = invoke(dir.path(), &["kill", "box-0", "p1-0"]).await;

    assert_eq!(killed.code, 0);
    Ok(())
}

#[tokio::test]
async fn a_local_forward_reports_the_address_and_returns() -> Result<()> {
    // Nothing is held open on a local host, so blocking would look like a
    // working tunnel and be a hang.
    let dir = temp_dir()?;

    let forwarded = invoke(dir.path(), &["forward", "7788"]).await;

    assert_eq!(forwarded.code, 0);
    assert_eq!(forwarded.out.trim(), "127.0.0.1:7788");
    Ok(())
}

#[tokio::test]
async fn spawning_into_a_sandbox_that_cannot_detach_is_refused() -> Result<()> {
    // A namespace box is a record and a bound directory rather than a running
    // container, so a backgrounded process would not survive to be found. It
    // says so instead.
    let dir = temp_dir()?;
    let created = invoke(
        dir.path(),
        &["create", "--sandbox", "namespace", "--dir", "/tmp"],
    )
    .await;
    if created.code != 0 {
        return Ok(()); // No bubblewrap on this host.
    }

    let spawned = invoke(dir.path(), &["spawn", "box-0", "sleep", "30"]).await;

    assert_eq!(spawned.code, EXIT_TINYBOX_ERROR);
    assert!(spawned.err.contains("detached processes"), "{}", spawned.err);
    Ok(())
}
