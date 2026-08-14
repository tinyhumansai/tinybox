//! End-to-end tests that drive the real `tinybox` binary.
//!
//! Everything else in this crate tests `tinybox_cli::run` in-process, which
//! cannot exercise `main.rs` — the runtime setup, the stream locking, and the
//! conversion of a code into a process exit status. Spawning the binary covers
//! those, and it is also the only test that proves the milestone the way a user
//! meets it: create a box, run something in it, and see the result.
//!
//! `CARGO_BIN_EXE_tinybox` is set by cargo for integration tests, and
//! `cargo llvm-cov` instruments workspace binaries, so this run counts toward
//! coverage rather than leaving `main.rs` uncovered.
//!
//! Tests return `io::Result` and use `?` rather than `expect`, because the
//! no-panic lints apply to every target in this workspace.

use std::io;
use std::path::Path;
use std::process::{Command, Output};

use tempfile::TempDir;

/// Run the real binary with a store inside `dir`.
fn tinybox(dir: &Path, args: &[&str]) -> io::Result<Output> {
    Command::new(env!("CARGO_BIN_EXE_tinybox"))
        .arg("--store")
        .arg(dir.join("boxes.json"))
        .args(args)
        .output()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn a_box_is_created_used_and_destroyed_through_the_binary() -> io::Result<()> {
    let state = TempDir::new()?;
    let workspace = TempDir::new()?;
    let workspace_path = workspace.path().display().to_string();

    let created = tinybox(state.path(), &["create", "--dir", &workspace_path])?;
    assert!(created.status.success(), "{}", stderr(&created));
    assert_eq!(stdout(&created).trim(), "box-0");

    // A separate process, reading the box the first one recorded.
    let executed = tinybox(state.path(), &["exec", "box-0", "echo", "from-the-box"])?;
    assert!(executed.status.success(), "{}", stderr(&executed));
    assert_eq!(stdout(&executed).trim(), "from-the-box");

    let listed = tinybox(state.path(), &["ls"])?;
    assert!(stdout(&listed).contains("box-0"));

    let removed = tinybox(state.path(), &["rm", "box-0"])?;
    assert!(removed.status.success());
    assert!(stdout(&tinybox(state.path(), &["ls"])?).is_empty());
    Ok(())
}

#[test]
fn the_command_exit_status_becomes_the_process_exit_status() -> io::Result<()> {
    let state = TempDir::new()?;

    let executed = tinybox(
        state.path(),
        &["run", "--dir", "/tmp", "sh", "-c", "exit 9"],
    )?;

    // A code that is not forwarded shows up here and nowhere else.
    assert_eq!(executed.status.code(), Some(9));
    Ok(())
}

#[test]
fn output_survives_being_piped() -> io::Result<()> {
    let state = TempDir::new()?;

    let executed = tinybox(
        state.path(),
        &["run", "--dir", "/tmp", "sh", "-c", "echo piped"],
    )?;

    // Not a terminal, so stdout is block-buffered; this fails if `main` exits
    // without flushing.
    assert_eq!(stdout(&executed).trim(), "piped");
    assert!(executed.status.success());
    Ok(())
}

#[test]
fn a_tinybox_failure_is_distinguishable_from_a_command_failure() -> io::Result<()> {
    let state = TempDir::new()?;

    let missing = tinybox(state.path(), &["exec", "box-9", "true"])?;
    assert_eq!(missing.status.code(), Some(70));
    assert!(stderr(&missing).contains("no box with id box-9"));

    let failed = tinybox(
        state.path(),
        &["run", "--dir", "/tmp", "sh", "-c", "exit 1"],
    )?;
    assert_eq!(failed.status.code(), Some(1));
    Ok(())
}

#[test]
fn help_reaches_stdout_and_names_every_command() -> io::Result<()> {
    let state = TempDir::new()?;

    let help = tinybox(state.path(), &["--help"])?;

    assert!(help.status.success());
    // On stdout, not stderr, or `tinybox --help | less` comes back empty.
    let text = stdout(&help);
    for command in ["create", "exec", "ls", "inspect", "rm", "run"] {
        assert!(text.contains(command), "help should mention {command}");
    }
    Ok(())
}

#[test]
fn the_default_store_location_is_used_when_none_is_given() -> io::Result<()> {
    let state = TempDir::new()?;

    // No `--store`, so the path comes from the environment. Setting it on the
    // child avoids mutating this process's own environment, which would need
    // `unsafe` in Rust 2024.
    let created = Command::new(env!("CARGO_BIN_EXE_tinybox"))
        .env("TINYBOX_STATE_DIR", state.path())
        .args(["create", "--dir", "/tmp"])
        .output()?;

    assert!(created.status.success(), "{}", stderr(&created));
    assert_eq!(stdout(&created).trim(), "box-0");
    assert!(state.path().join("boxes.json").exists());
    Ok(())
}
