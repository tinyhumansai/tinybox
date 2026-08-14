//! Tests for the local host.
//!
//! These spawn real processes, but only ones every supported platform ships and
//! whose behavior is fixed, so they stay deterministic and need no network,
//! clock, or ordering assumptions.

use std::path::Path;

use tinybox_core::{Error, ExecRequest, Host, Result};

use super::{LocalHost, NAME};

#[test]
fn it_reports_its_name() {
    assert_eq!(LocalHost::new().name(), "local");
    assert_eq!(LocalHost.name(), NAME);
}

#[tokio::test]
async fn it_runs_a_command_and_captures_stdout() -> Result<()> {
    let output = LocalHost::new()
        .run(&ExecRequest::new(["echo", "hello"]))
        .await?;

    assert!(output.succeeded());
    assert_eq!(output.exit_code, 0);
    assert_eq!(output.stdout_lossy().trim(), "hello");
    assert!(output.stderr.is_empty());
    Ok(())
}

#[tokio::test]
async fn a_non_zero_exit_is_a_result_not_an_error() -> Result<()> {
    // `false` exists to fail. The host must report that as an outcome rather
    // than an Err, or callers can never distinguish a failing command from an
    // unreachable machine.
    let output = LocalHost::new().run(&ExecRequest::new(["false"])).await?;

    assert!(!output.succeeded());
    assert_ne!(output.exit_code, 0);
    Ok(())
}

#[tokio::test]
async fn stderr_is_captured_separately_from_stdout() -> Result<()> {
    let output = LocalHost::new()
        .run(&ExecRequest::new([
            "sh",
            "-c",
            "echo out; echo err >&2; exit 3",
        ]))
        .await?;

    assert_eq!(output.exit_code, 3);
    assert_eq!(output.stdout_lossy().trim(), "out");
    assert_eq!(output.stderr_lossy().trim(), "err");
    Ok(())
}

#[tokio::test]
async fn a_missing_program_is_an_io_error() -> Result<()> {
    let outcome = LocalHost::new()
        .run(&ExecRequest::new(["tinybox-no-such-program"]))
        .await;

    assert!(matches!(
        outcome,
        Err(Error::Io {
            operation: "spawn",
            ..
        })
    ));
    Ok(())
}

#[tokio::test]
async fn a_command_with_no_program_is_refused_before_spawning() {
    let empty: Vec<String> = Vec::new();

    assert_eq!(
        LocalHost::new().run(&ExecRequest::new(empty)).await.err(),
        Some(Error::EmptyCommand {
            sandbox: NAME.to_owned()
        })
    );
}

#[tokio::test]
async fn it_runs_in_the_requested_directory() -> Result<()> {
    let dir = tempfile::tempdir().map_err(|error| Error::io("tempdir", &error))?;
    // macOS reports /var as a symlink to /private/var, so compare against the
    // resolved path rather than the one handed to tempfile.
    let expected = dir
        .path()
        .canonicalize()
        .map_err(|error| Error::io("canonicalize", &error))?;

    let output = LocalHost::new()
        .run(&ExecRequest::new(["pwd"]).with_cwd(dir.path()))
        .await?;

    assert_eq!(
        Path::new(output.stdout_lossy().trim()).canonicalize().ok(),
        Some(expected)
    );
    Ok(())
}

#[tokio::test]
async fn an_unreadable_working_directory_is_an_io_error() -> Result<()> {
    let outcome = LocalHost::new()
        .run(&ExecRequest::new(["pwd"]).with_cwd("/tinybox-no-such-directory"))
        .await;

    assert!(matches!(outcome, Err(Error::Io { .. })));
    Ok(())
}

#[tokio::test]
async fn requested_variables_reach_the_child() -> Result<()> {
    let output = LocalHost::new()
        .run(
            &ExecRequest::new(["sh", "-c", "printf %s \"$TINYBOX_TEST\""])
                .with_env("TINYBOX_TEST", "set-by-request"),
        )
        .await?;

    assert_eq!(output.stdout_lossy(), "set-by-request");
    Ok(())
}

#[tokio::test]
async fn the_child_inherits_the_parent_environment() -> Result<()> {
    // PATH lookup depends on this, so it is worth pinning rather than leaving
    // to chance.
    let output = LocalHost::new()
        .run(&ExecRequest::new(["sh", "-c", "printf %s \"$PATH\""]))
        .await?;

    assert!(!output.stdout.is_empty());
    Ok(())
}

#[tokio::test]
async fn arguments_are_passed_through_without_shell_interpretation() -> Result<()> {
    // The argument vector is handed to the process directly, so a value that
    // would be glob-expanded or word-split by a shell arrives intact.
    let output = LocalHost::new()
        .run(&ExecRequest::new(["echo", "a b*c;d $HOME"]))
        .await?;

    assert_eq!(output.stdout_lossy().trim(), "a b*c;d $HOME");
    Ok(())
}

#[tokio::test]
async fn a_child_reading_stdin_does_not_hang() -> Result<()> {
    // stdin is null, so `cat` sees EOF immediately instead of blocking on a
    // terminal no one is attached to.
    let output = LocalHost::new().run(&ExecRequest::new(["cat"])).await?;

    assert!(output.succeeded());
    assert!(output.stdout.is_empty());
    Ok(())
}

#[tokio::test]
async fn output_larger_than_a_pipe_buffer_is_collected() -> Result<()> {
    // Reading the two pipes in sequence would deadlock here: the child fills
    // one buffer while the parent waits on the other.
    let output = LocalHost::new()
        .run(&ExecRequest::new([
            "sh",
            "-c",
            "yes tinybox | head -c 200000; yes err | head -c 200000 >&2",
        ]))
        .await?;

    assert_eq!(output.stdout.len(), 200_000);
    assert_eq!(output.stderr.len(), 200_000);
    Ok(())
}

#[tokio::test]
async fn a_signal_terminated_process_reports_an_unmistakable_code() -> Result<()> {
    let output = LocalHost::new()
        .run(&ExecRequest::new(["sh", "-c", "kill -TERM $$"]))
        .await?;

    assert!(!output.succeeded());
    // Either the shell reports 128+15 itself, or the process died signalled and
    // we substitute 128. Both are outside the success range.
    assert!(output.exit_code >= 128);
    Ok(())
}
