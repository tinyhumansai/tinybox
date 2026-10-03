//! Tests for the Linux Landlock backend. They enforce for real, so each one
//! returns early (with a note) on a kernel without Landlock.

use super::*;
use std::path::Path;
use std::process::Stdio;

fn available() -> bool {
    let ok = LandlockBackend::new().is_available();
    if !ok {
        eprintln!("skipped: Landlock is not supported by this kernel");
    }
    ok
}

/// Runs `script` under `sh -c` inside `jail`, returning whether it exited 0.
fn sh(jail: &Jail, script: &str) -> io::Result<bool> {
    let mut cmd = Command::new("/bin/sh");
    cmd.arg("-c").arg(script);
    Ok(LandlockBackend::new().spawn(jail, cmd)?.wait()?.success())
}

fn jail_for(root: &Path) -> Jail {
    let mut jail = Jail::new(root, "landlock-test");
    jail.canonicalize().unwrap();
    jail
}

#[test]
fn reports_name_and_probes_the_kernel() {
    let backend = LandlockBackend::new();
    assert_eq!(backend.name(), "landlock");
    // The probe must agree with a hard-requirement ruleset creation.
    assert_eq!(backend.is_available(), imp::kernel_supports_landlock());
}

#[test]
fn shell_starts_with_only_the_baseline_system_paths() -> io::Result<()> {
    if !available() {
        return Ok(());
    }
    let root = tempfile::tempdir()?;
    assert!(sh(
        &jail_for(root.path()),
        "ls /usr/bin >/dev/null && echo hi >/dev/null"
    )?);
    Ok(())
}

#[test]
fn writes_inside_the_root_succeed_and_outside_fail() -> io::Result<()> {
    if !available() {
        return Ok(());
    }
    let root = tempfile::tempdir()?;
    let outside = tempfile::tempdir()?;
    let jail = jail_for(root.path());

    assert!(sh(
        &jail,
        &format!("echo ok > '{}'", root.path().join("in").display())
    )?);
    assert_eq!(std::fs::read_to_string(root.path().join("in"))?, "ok\n");

    let target = outside.path().join("out");
    assert!(!sh(&jail, &format!("echo no > '{}'", target.display()))?);
    assert!(!target.exists(), "write outside the root must be denied");
    Ok(())
}

#[test]
fn reads_outside_granted_paths_are_denied() -> io::Result<()> {
    if !available() {
        return Ok(());
    }
    let root = tempfile::tempdir()?;
    let secret_dir = tempfile::tempdir()?;
    let secret = secret_dir.path().join("secret");
    std::fs::write(&secret, "token")?;
    let jail = jail_for(root.path());
    assert!(!sh(
        &jail,
        &format!("cat '{}' >/dev/null", secret.display())
    )?);
    Ok(())
}

#[test]
fn read_only_paths_are_readable_but_not_writable() -> io::Result<()> {
    if !available() {
        return Ok(());
    }
    let root = tempfile::tempdir()?;
    let shared = tempfile::tempdir()?;
    std::fs::write(shared.path().join("data"), "v")?;
    let jail = jail_for(root.path()).add_read_only(shared.path());
    let mut jail = jail;
    jail.canonicalize()?;

    assert!(sh(
        &jail,
        &format!("cat '{}' >/dev/null", shared.path().join("data").display())
    )?);
    assert!(!sh(
        &jail,
        &format!("echo x > '{}'", shared.path().join("new").display())
    )?);
    assert!(!shared.path().join("new").exists());
    Ok(())
}

#[test]
fn read_write_paths_outside_the_root_are_writable() -> io::Result<()> {
    if !available() {
        return Ok(());
    }
    let root = tempfile::tempdir()?;
    let scratch = tempfile::tempdir()?;
    let denied = tempfile::tempdir()?;
    let mut jail = Jail::new(root.path(), "landlock-rw").add_read_write(scratch.path());
    jail.canonicalize()?;

    let write = |dir: &Path| sh(&jail, &format!("echo ok > '{}'", dir.join("out").display()));
    assert!(write(scratch.path())?, "read_write path must be writable");
    assert_eq!(std::fs::read_to_string(scratch.path().join("out"))?, "ok\n");
    assert!(
        !write(denied.path())?,
        "paths not granted must stay unwritable"
    );
    assert!(!denied.path().join("out").exists());
    Ok(())
}

#[test]
fn missing_read_write_path_fails_the_spawn_but_missing_read_only_is_skipped() -> io::Result<()> {
    if !available() {
        return Ok(());
    }
    let root = tempfile::tempdir()?;
    let missing = root.path().join("does-not-exist");

    let jail = jail_for(root.path()).add_read_write(&missing);
    let error = LandlockBackend::new()
        .spawn(&jail, Command::new("/bin/true"))
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::NotFound);

    let jail = jail_for(root.path()).add_read_only(&missing);
    assert!(sh(&jail, "true")?);
    Ok(())
}

#[test]
fn confinement_does_not_leak_into_the_parent_process() -> io::Result<()> {
    if !available() {
        return Ok(());
    }
    let root = tempfile::tempdir()?;
    let outside = tempfile::tempdir()?;
    assert!(sh(&jail_for(root.path()), "true")?);
    // The calling thread (and the process) must still be able to write anywhere.
    std::fs::write(outside.path().join("parent"), "still free")?;
    Ok(())
}

#[test]
fn null_stdio_and_environment_pass_through() -> io::Result<()> {
    if !available() {
        return Ok(());
    }
    let root = tempfile::tempdir()?;
    let jail = jail_for(root.path());
    let mut cmd = Command::new("/bin/sh");
    cmd.arg("-c")
        .arg("echo $JAIL_TEST_VAR > out")
        .env("JAIL_TEST_VAR", "from-host")
        .current_dir(root.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    assert!(LandlockBackend::new().spawn(&jail, cmd)?.wait()?.success());
    assert_eq!(
        std::fs::read_to_string(root.path().join("out"))?,
        "from-host\n"
    );
    Ok(())
}

#[test]
fn child_cannot_regain_privileges_through_no_new_privs() -> io::Result<()> {
    if !available() {
        return Ok(());
    }
    let root = tempfile::tempdir()?;
    // NoNewPrivs is reported in /proc/self/status, which is outside the
    // baseline, so grant /proc read access just for this probe.
    let jail = jail_for(root.path()).add_read_only("/proc");
    let mut cmd = Command::new("/bin/sh");
    cmd.arg("-c")
        .arg("grep -q '^NoNewPrivs:[[:space:]]*1' /proc/self/status");
    assert!(LandlockBackend::new().spawn(&jail, cmd)?.wait()?.success());
    Ok(())
}

#[cfg(not(feature = "landlock"))]
#[test]
fn without_the_feature_spawn_is_unsupported_and_never_runs_unconfined() {
    let root = tempfile::tempdir().unwrap();
    let marker = root.path().join("ran");
    let mut cmd = Command::new("/bin/sh");
    cmd.arg("-c").arg(format!("touch '{}'", marker.display()));
    let backend = LandlockBackend::new();
    assert!(!backend.is_available());
    let error = backend.spawn(&jail_for(root.path()), cmd).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    assert!(!marker.exists());
}

#[test]
fn baseline_lets_the_resolver_config_be_read_through_its_symlink() -> io::Result<()> {
    if !available() {
        return Ok(());
    }
    let root = tempfile::tempdir()?;
    // Resolves symlinks like a DNS lookup does: /etc/resolv.conf may point
    // into /run/systemd/resolve.
    assert!(sh(
        &jail_for(root.path()),
        "cat /etc/resolv.conf >/dev/null"
    )?);
    Ok(())
}

/// File grants must enforce fully without granting their parent directory.
#[test]
fn individual_file_grants_preserve_read_only_and_read_write_access() -> io::Result<()> {
    if !available() {
        return Ok(());
    }
    let root = tempfile::tempdir()?;
    let outside = tempfile::tempdir()?;
    let readable = outside.path().join("readable");
    let writable = outside.path().join("writable");
    let denied = outside.path().join("denied");
    std::fs::write(&readable, "read only")?;
    std::fs::write(&writable, "writable")?;
    std::fs::write(&denied, "unchanged")?;
    let jail = jail_for(root.path())
        .add_read_only(&readable)
        .add_read_write(&writable);
    assert!(sh(
        &jail,
        &format!("cat '{}' >/dev/null", readable.display())
    )?);
    assert!(!sh(
        &jail,
        &format!("truncate -s 0 '{}'", readable.display())
    )?);
    assert!(sh(
        &jail,
        &format!("truncate -s 0 '{}'", writable.display())
    )?);
    assert!(!sh(
        &jail,
        &format!("truncate -s 0 '{}'", denied.display())
    )?);
    assert_eq!(std::fs::read_to_string(&readable)?, "read only");
    assert_eq!(std::fs::read_to_string(&writable)?, "");
    assert_eq!(std::fs::read_to_string(&denied)?, "unchanged");
    Ok(())
}
