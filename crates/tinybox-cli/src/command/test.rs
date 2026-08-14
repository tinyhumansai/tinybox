//! Tests for argument parsing and command dispatch.
//!
//! Every case drives [`run`] with an explicit `--store` under a temporary
//! directory, so no test touches the caller's real box records and none of
//! them depend on each other's state.

use std::io::{self, Write};
use std::path::Path;

use clap::CommandFactory;
use tempfile::TempDir;
use tinybox_core::{Error, Result};

use super::{Cli, EXIT_TINYBOX_ERROR, exit_code, run, workspace};

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
fn a_workspace_that_is_not_a_directory_still_renders() -> Result<()> {
    use tinybox_core::{
        BoxId, BoxInfo, BoxSpec, BoxState, HostRef, Placement, SandboxRef, WorkspaceSource,
    };

    // The CLI only creates `LocalDir` boxes, but a store written by another
    // adapter can hold any source, and `ls` must not omit the column for it.
    let spec = BoxSpec::new(
        Placement::new(HostRef::new("local")?, SandboxRef::new("docker")?),
        WorkspaceSource::OciImage("alpine:3".to_owned()),
    );
    let info = BoxInfo::new(BoxId::new("box-0")?, BoxState::Ready, spec);

    assert!(workspace(&info).contains("alpine:3"));
    Ok(())
}
