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

#[tokio::test]
async fn a_payload_reaches_the_child_on_standard_input() -> Result<()> {
    let output = LocalHost::new()
        .run(&ExecRequest::new(["cat"]).with_stdin("piped in"))
        .await?;

    assert!(output.succeeded());
    assert_eq!(output.stdout_lossy(), "piped in");
    Ok(())
}

#[tokio::test]
async fn a_child_reading_to_end_of_file_is_not_left_waiting() -> Result<()> {
    // The pipe has to be closed after the payload is written. Without that,
    // `wc` would block forever waiting for input that has already all been
    // sent, and this test would hang rather than fail.
    let output = LocalHost::new()
        .run(&ExecRequest::new(["wc", "-c"]).with_stdin("12345"))
        .await?;

    assert_eq!(output.stdout_lossy().trim(), "5");
    Ok(())
}

#[tokio::test]
async fn a_binary_payload_survives_intact() -> Result<()> {
    // A tar stream is not text, so the bytes must not be transformed.
    let payload: Vec<u8> = (0u8..=255).collect();
    let output = LocalHost::new()
        .run(&ExecRequest::new(["cat"]).with_stdin(payload.clone()))
        .await?;

    assert_eq!(output.stdout, payload);
    Ok(())
}

#[tokio::test]
async fn a_payload_larger_than_a_pipe_buffer_is_delivered() -> Result<()> {
    // Writing must not deadlock against a child that is still reading: the
    // payload is larger than the 64 KiB pipe buffer.
    let payload = vec![b'x'; 300_000];
    let output = LocalHost::new()
        .run(&ExecRequest::new(["wc", "-c"]).with_stdin(payload))
        .await?;

    assert_eq!(output.stdout_lossy().trim(), "300000");
    Ok(())
}

#[tokio::test]
async fn a_command_with_a_payload_still_reports_a_failing_status() -> Result<()> {
    let output = LocalHost::new()
        .run(&ExecRequest::new(["sh", "-c", "cat >/dev/null; exit 4"]).with_stdin("ignored"))
        .await?;

    assert_eq!(output.exit_code, 4);
    Ok(())
}

#[tokio::test]
async fn a_command_that_ignores_its_input_does_not_fail_the_write() -> Result<()> {
    // `true` exits before reading, so the write end breaks. A broken pipe here
    // is the child's choice, not an error worth surfacing.
    let outcome = LocalHost::new()
        .run(&ExecRequest::new(["true"]).with_stdin(vec![b'y'; 200_000]))
        .await;

    // Either the write lands before the child exits, or it fails with EPIPE.
    // Both are acceptable; hanging is not.
    assert!(outcome.is_ok() || matches!(outcome, Err(Error::Io { .. })));
    Ok(())
}

#[tokio::test]
async fn a_local_forward_is_the_address_itself() -> Result<()> {
    // Nothing to tunnel: a port published on this machine is already reachable
    // from it. The method exists so a caller can ask any host for reach without
    // first asking which kind of host it has.
    let forwarded = LocalHost::new().forward(([127, 0, 0, 1], 7788).into()).await?;

    assert_eq!(forwarded.local_addr(), ([127, 0, 0, 1], 7788).into());
    assert!(forwarded.is_direct());
    Ok(())
}
