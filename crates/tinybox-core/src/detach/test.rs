//! Tests for the detached-process mechanism.
//!
//! The command builders are pure, so the encoding is pinned here exactly. The
//! part that needs a real shell — that the wrapper actually backgrounds a
//! process and that the pid it records is the right one — is checked at the
//! bottom against `sh` itself, skipped where no shell exists.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use super::{DEFAULT_GRACE, PID_DIR, RUNNING, mint, pid_file, probe, start, stop};
use crate::error::{Error, Result};
use crate::identity::ProcessId;
use crate::runtime::ExecRequest;

fn process() -> Result<ProcessId> {
    ProcessId::new("p1-0")
}

#[test]
fn a_minted_id_is_valid_and_distinct() -> Result<()> {
    let first = mint();
    let second = mint();

    assert_ne!(first, second);
    // Round-trips through the validating constructor, which is what makes the
    // fallback in `mint` unreachable rather than merely unlikely.
    ProcessId::new(first.as_str())?;
    Ok(())
}

#[test]
fn the_pid_file_lives_outside_the_workspace() -> Result<()> {
    // Runtime bookkeeping in the workspace would be synced back out, or fail
    // on a read-only mount.
    assert_eq!(pid_file(&process()?), format!("{PID_DIR}/tinybox-p1-0.pid"));
    Ok(())
}

#[test]
fn starting_runs_through_a_shell_because_backgrounding_needs_one() -> Result<()> {
    let started = start(&process()?, &ExecRequest::new(["sleep", "60"]))?;

    assert_eq!(started.program(), Some("/bin/sh"));
    assert_eq!(started.argv[1], "-c");
    Ok(())
}

#[test]
fn the_pid_is_recorded_before_the_wrapper_exits() -> Result<()> {
    // Otherwise a caller could ask "is it running" and be told "gone" about a
    // process that had started perfectly well.
    let started = start(&process()?, &ExecRequest::new(["sleep", "60"]))?;
    let line = &started.argv[2];

    assert!(line.contains("& echo $! >"), "{line:?}");
    assert!(
        line.ends_with(&format!("'{PID_DIR}/tinybox-p1-0.pid'")),
        "{line:?}"
    );
    Ok(())
}

#[test]
fn output_is_discarded_so_a_full_pipe_cannot_block_the_process() -> Result<()> {
    let started = start(&process()?, &ExecRequest::new(["server"]))?;

    assert!(started.argv[2].contains("</dev/null >/dev/null 2>&1"));
    Ok(())
}

#[test]
fn the_command_is_quoted_so_a_filename_cannot_inject() -> Result<()> {
    let started = start(&process()?, &ExecRequest::new(["echo", "; rm -rf /"]))?;

    // One quoted word, so the semicolon is data.
    assert!(
        started.argv[2].contains(r"'echo' '; rm -rf /'"),
        "{:?}",
        started.argv[2]
    );
    Ok(())
}

#[test]
fn the_working_directory_and_environment_reach_the_backgrounded_command() -> Result<()> {
    let mut request = ExecRequest::new(["server"]).with_cwd(Path::new("/srv/work"));
    request.env = BTreeMap::from([("PORT".to_owned(), "7788".to_owned())]);

    let started = start(&process()?, &request)?;

    assert!(started.argv[2].contains("cd '/srv/work' &&"));
    assert!(started.argv[2].contains("env 'PORT=7788'"));
    Ok(())
}

#[test]
fn a_caller_payload_does_not_reach_the_wrapper() -> Result<()> {
    // The backgrounded command already gets /dev/null; a payload here would
    // feed the wrapping shell instead, which is never what a caller meant.
    let request = ExecRequest::new(["server"]).with_stdin(b"payload".to_vec());

    let started = start(&process()?, &request)?;

    assert_eq!(started.stdin, None);
    Ok(())
}

#[test]
fn an_empty_command_is_refused_here_rather_than_by_a_backend() -> Result<()> {
    let outcome = start(&process()?, &ExecRequest::new(Vec::<String>::new()));

    assert_eq!(
        outcome.err(),
        Some(Error::EmptyCommand {
            sandbox: "detach".to_owned()
        })
    );
    Ok(())
}

#[test]
fn probing_asks_the_kernel_rather_than_trusting_the_file() -> Result<()> {
    // A pid file outlives its process; signal 0 is the existence check.
    let request = probe(&process()?);

    assert!(request.argv[2].contains("kill -0"));
    assert!(request.argv[2].contains(RUNNING));
    Ok(())
}

#[test]
fn stopping_escalates_and_always_clears_the_pid_file() -> Result<()> {
    let request = stop(&process()?, DEFAULT_GRACE);
    let line = &request.argv[2];

    assert!(line.contains("kill -TERM"), "{line:?}");
    assert!(line.contains("kill -KILL"), "{line:?}");
    // Left behind, a stale file would make a later probe answer about whatever
    // process inherits that pid next.
    assert!(line.contains("rm -f"), "{line:?}");
    // Stopping something already stopped is the outcome the caller wanted.
    assert!(line.contains("exit 0"), "{line:?}");
    Ok(())
}

#[test]
fn a_sub_second_grace_still_waits_a_whole_second() -> Result<()> {
    // `seq 0` would produce no iterations, so TERM and KILL would land back to
    // back and the graceful path would never happen.
    let request = stop(&process()?, Duration::from_millis(10));

    assert!(request.argv[2].contains("seq 1"), "{:?}", request.argv[2]);
    Ok(())
}

/// Run one of these command builders through a real `sh`, returning stdout.
///
/// Returns `None` where no shell exists, so the encoding tests above remain
/// the guarantee on such a host.
fn run(request: &ExecRequest) -> Option<String> {
    let output = std::process::Command::new(&request.argv[0])
        .args(&request.argv[1..])
        .output()
        .ok()?;
    Some(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

#[test]
fn a_started_process_is_reported_running_and_then_stops() -> Result<()> {
    // The property the encoding tests cannot check: that this really does
    // background something, and that the recorded pid is that something's.
    let id = mint();
    let started = start(&id, &ExecRequest::new(["sleep", "30"]))?;

    if run(&started).is_none() {
        return Ok(()); // No shell on this host.
    }

    assert_eq!(run(&probe(&id)).as_deref(), Some(RUNNING));

    run(&stop(&id, Duration::from_secs(1)));
    assert_eq!(run(&probe(&id)).as_deref(), Some("gone"));
    Ok(())
}

#[test]
fn probing_a_process_that_was_never_started_answers_gone() {
    let id = mint();

    if let Some(answer) = run(&probe(&id)) {
        assert_eq!(answer, "gone");
    }
}
