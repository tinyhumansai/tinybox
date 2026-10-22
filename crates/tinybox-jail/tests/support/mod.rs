//! Helpers shared by the bubblewrap integration tests.

use std::io;
use std::path::Path;
use std::process::Command;
use std::time::Instant;

use tinybox_jail::{BubblewrapBackend, Jail, JailBackend, spawn_captured_with};

/// The backend, `None` to skip, or an error when it is required but absent.
pub(crate) fn backend() -> io::Result<Option<BubblewrapBackend>> {
    let backend = BubblewrapBackend::new();
    if backend.is_available() {
        return Ok(Some(backend));
    }
    if std::env::var_os("TINYBOX_REQUIRE_BWRAP").is_some_and(|v| v == "1") {
        return Err(io::Error::other(
            "TINYBOX_REQUIRE_BWRAP=1 but no working bwrap (install bubblewrap and allow \
             unprivileged user namespaces)",
        ));
    }
    eprintln!("skipped: bwrap or unprivileged user namespaces unavailable");
    Ok(None)
}

pub(crate) fn done(name: &str, start: Instant) {
    eprintln!("[bwrap-real] {name} ok in {:?}", start.elapsed());
}

pub(crate) fn run(
    backend: &BubblewrapBackend,
    jail: &Jail,
    cmd: Command,
) -> io::Result<std::process::Output> {
    backend
        .require(jail)
        .map_err(|error| io::Error::new(io::ErrorKind::Unsupported, error))?;
    spawn_captured_with(backend, jail, cmd)?.wait_with_output()
}

/// Output of a script that first printed `started`: `(exit success, stdout
/// after the marker)`.
///
/// # Errors
/// An error when the marker is missing, so a sandbox that failed to start can
/// never satisfy a negative assertion ("the secret is not readable") by
/// producing no output at all.
pub(crate) fn started(out: &std::process::Output) -> io::Result<(bool, String)> {
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let Some(rest) = text.strip_prefix("started\n") else {
        return Err(io::Error::other(format!(
            "the sandboxed script never started (status {:?}): stdout {text:?}, stderr {:?}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        )));
    };
    Ok((out.status.success(), rest.to_owned()))
}

/// Runs `script` under `sh -c` inside `jail` after a `started` marker.
pub(crate) fn sh(
    backend: &BubblewrapBackend,
    jail: &Jail,
    script: &str,
) -> io::Result<(bool, String)> {
    let mut cmd = Command::new("/bin/sh");
    cmd.arg("-c").arg(format!("echo started; {script}"));
    started(&run(backend, jail, cmd)?)
}

pub(crate) fn jail(root: &Path) -> Jail {
    Jail::new(root, "bwrap-it")
}

/// Like `sh` but returns the spawn error kind when the jail is refused.
pub(crate) fn refused(backend: &BubblewrapBackend, jail: &Jail) -> Option<io::ErrorKind> {
    let mut cmd = Command::new("/bin/true");
    cmd.arg("x");
    spawn_captured_with(backend, jail, cmd)
        .err()
        .map(|e| e.kind())
}
