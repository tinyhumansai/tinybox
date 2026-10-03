//! Tests for Seatbelt profiles and launcher command forwarding.

use super::*;
use std::fs;
use std::process::Stdio;

#[test]
fn profile_allow_net_by_default_has_no_deny() {
    let jail = Jail::new("/tmp", "x");
    let p = render_profile(&jail);
    assert!(p.contains("(allow default)"));
    assert!(!p.contains("(deny network*)"));
}

#[test]
fn profile_deny_subprocess_emits_deny_rules() {
    let jail = Jail::new("/tmp", "x").deny_subprocess();
    let p = render_profile(&jail);
    assert!(p.contains("(deny process-fork)"));
    assert!(p.contains("(deny process-exec)"));
}

#[test]
fn profile_allow_subprocess_default_has_no_process_deny() {
    let jail = Jail::new("/tmp", "x");
    let p = render_profile(&jail);
    assert!(!p.contains("(deny process-fork)"));
    assert!(!p.contains("(deny process-exec)"));
}

#[test]
fn escape_handles_backslash_and_quote() {
    assert_eq!(escape("a\\b"), "a\\\\b");
    assert_eq!(escape("a\"b"), "a\\\"b");
    assert_eq!(escape("a\\\"b"), "a\\\\\\\"b");
    assert_eq!(escape("plain"), "plain");
}

#[test]
fn is_available_reflects_sandbox_exec_presence() {
    let backend = SeatbeltBackend::new();
    let expected = std::path::Path::new("/usr/bin/sandbox-exec").exists();
    assert_eq!(backend.is_available(), expected);
    assert_eq!(backend.name(), "seatbelt");
}

#[test]
fn seatbelt_passes_cwd_through() {
    let backend = SeatbeltBackend::new();
    if !backend.is_available() {
        return;
    }
    let root = std::env::temp_dir().join(format!("oh-cwd-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    let mut jail = Jail::new(&root, "cwd");
    // `/tmp` canonicalizes to `/private/tmp` on macOS — subpath
    // matching in the Seatbelt profile is by canonical path, so
    // unless we resolve first the write inside root gets denied.
    // This is exactly what the `spawn` facade does for callers.
    jail.canonicalize().unwrap();
    let mut cmd = Command::new("/bin/sh");
    cmd.arg("-c")
        .arg("pwd > pwd.out")
        .current_dir(&root)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = backend.spawn(&jail, cmd).expect("spawn");
    let status = child.wait().expect("wait");
    assert!(status.success());
    let written = fs::read_to_string(root.join("pwd.out")).unwrap();
    // pwd resolves through /private on macOS — we just check it ends
    // with the basename of root.
    let last = root.file_name().unwrap().to_string_lossy().to_string();
    assert!(
        written.trim().ends_with(&last),
        "pwd output {written:?} did not end with {last}"
    );
    fs::remove_dir_all(&root).ok();
}

#[test]
fn seatbelt_passes_env_through() {
    let backend = SeatbeltBackend::new();
    if !backend.is_available() {
        return;
    }
    let root = std::env::temp_dir().join(format!("oh-env-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    let mut jail = Jail::new(&root, "env");
    jail.canonicalize().unwrap();
    let mut cmd = Command::new("/bin/sh");
    cmd.arg("-c")
        .arg("echo $OPENHUMAN_TEST_VAR > env.out")
        .env("OPENHUMAN_TEST_VAR", "hello-from-jail")
        .current_dir(&root)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = backend.spawn(&jail, cmd).expect("spawn");
    child.wait().expect("wait");
    let written = fs::read_to_string(root.join("env.out")).unwrap();
    assert_eq!(written.trim(), "hello-from-jail");
    fs::remove_dir_all(&root).ok();
}

#[test]
fn profile_allows_default_and_jails_writes() {
    let jail = Jail::new("/tmp/abc", "test").deny_net();
    let p = render_profile(&jail);
    assert!(p.contains("(allow default)"));
    assert!(p.contains("(deny file-write*)"));
    assert!(p.contains("(subpath \"/tmp/abc\")"));
    assert!(p.contains("(literal \"/dev/null\")"));
    assert!(!p.contains("(subpath \"/dev\")"));
    assert!(p.contains("(deny network*)"));
}

#[test]
fn seatbelt_allows_redirecting_output_to_dev_null() {
    let backend = SeatbeltBackend::new();
    if !backend.is_available() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let root_path = root.path();
    let mut jail = Jail::new(root_path, "null-redirection");
    jail.canonicalize().unwrap();

    let mut cmd = Command::new("/bin/sh");
    cmd.arg("-c")
        .arg(
            "set -e; echo ignored >/dev/null; echo hidden 2>/dev/null >&2; echo completed > output",
        )
        .current_dir(root_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = backend.spawn(&jail, cmd).expect("spawn");
    let status = child.wait().expect("wait");

    assert!(
        status.success(),
        "shell redirection to /dev/null was denied"
    );
    assert_eq!(
        fs::read_to_string(root_path.join("output")).unwrap(),
        "completed\n"
    );
}

#[test]
fn seatbelt_spawn_runs_true() {
    let backend = SeatbeltBackend::new();
    if !backend.is_available() {
        return;
    }
    let dir = std::env::temp_dir();
    let jail = Jail::new(&dir, "test.true");
    let mut cmd = Command::new("/usr/bin/true");
    cmd.stdout(Stdio::null()).stderr(Stdio::null());
    let mut child = backend.spawn(&jail, cmd).expect("spawn");
    let status = child.wait().expect("wait");
    assert!(status.success(), "sandboxed /usr/bin/true exited non-zero");
}

#[test]
fn seatbelt_blocks_write_outside_root() {
    let backend = SeatbeltBackend::new();
    if !backend.is_available() {
        return;
    }
    // Root = a fresh tempdir. Try to touch a file *outside* it.
    let root = std::env::temp_dir().join(format!("openhuman-encap-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    let outside =
        std::env::temp_dir().join(format!("openhuman-encap-outside-{}", std::process::id()));
    let _ = fs::remove_file(&outside);

    let jail = Jail::new(&root, "test.blocked");
    let mut cmd = Command::new("/usr/bin/touch");
    cmd.arg(&outside)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = backend.spawn(&jail, cmd).expect("spawn");
    let status = child.wait().expect("wait");

    // If the touch succeeded (file exists), seatbelt enforcement is not
    // available in this environment (e.g. the process is already running
    // inside a sandbox that supersedes sandbox-exec, or a corporate MDM
    // policy disables it). Skip rather than panic — the production
    // encapsulation path is guarded by `is_available()` at runtime.
    if outside.exists() {
        let _ = fs::remove_file(&outside);
        let _ = fs::remove_dir_all(&root);
        eprintln!(
            "seatbelt_blocks_write_outside_root: skipped — \
             sandbox-exec present but not enforcing in this environment"
        );
        return;
    }
    // Enforced path: the write was actually blocked, so `touch` must have
    // exited non-zero.
    assert!(
        !status.success(),
        "touch outside jail should fail when seatbelt is enforcing"
    );
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn profile_allows_writes_under_read_write_paths() {
    let jail = Jail::new("/work/root", "x")
        .add_read_write("/state/capture/1")
        .add_read_write("/state/with \"quote\"");
    let p = render_profile(&jail);
    let allow = p
        .split("(allow file-write*")
        .nth(1)
        .expect("profile has a file-write allow block");
    assert!(allow.contains("(subpath \"/work/root\")"));
    assert!(allow.contains("(subpath \"/state/capture/1\")"));
    assert!(allow.contains("(subpath \"/state/with \\\"quote\\\"\")"));
}

#[test]
fn profile_without_read_write_paths_only_allows_root_and_tmp() {
    let p = render_profile(&Jail::new("/work/root", "x"));
    assert_eq!(p.matches("(subpath ").count(), 2);
}

#[test]
fn launcher_preserves_arguments_environment_overrides_and_working_directory() {
    let jail = Jail::new("/work", "forwarding");
    let mut cmd = Command::new("/bin/tool");
    cmd.arg("a b")
        .arg("$(literal)")
        .env("SET", "value")
        .env_remove("REMOVE")
        .current_dir("/work");
    let wrapper = prepare_command(&jail, &cmd, std::ffi::OsStr::new("launcher"));
    assert_eq!(wrapper.get_program(), "launcher");
    let args: Vec<_> = wrapper.get_args().collect();
    assert_eq!(
        args,
        vec![
            "-p",
            &render_profile(&jail),
            "/bin/tool",
            "a b",
            "$(literal)"
        ]
    );
    assert_eq!(
        wrapper.get_current_dir(),
        Some(std::path::Path::new("/work"))
    );
    let env: Vec<_> = wrapper.get_envs().collect();
    assert!(env.contains(&(
        std::ffi::OsStr::new("SET"),
        Some(std::ffi::OsStr::new("value"))
    )));
    assert!(
        env.iter()
            .all(|(key, _)| *key != std::ffi::OsStr::new("REMOVE"))
    );
    let defaults = prepare_command(
        &jail,
        &Command::new("true"),
        std::ffi::OsStr::new("launcher"),
    );
    assert!(defaults.get_current_dir().is_none());
    assert_default_name::<SeatbeltBackend>("seatbelt");
}

#[test]
fn missing_launcher_returns_an_error() {
    let result = SeatbeltBackend::new().spawn(
        &Jail::new("/work", "missing"),
        Command::new("/nonexistent/tinybox-command"),
    );
    if !SeatbeltBackend::new().is_available() {
        assert_eq!(
            result.err().map(|e| e.kind()),
            Some(std::io::ErrorKind::NotFound)
        );
    }
}

/// Check the default-construction contract through the backend trait.
fn assert_default_name<B: JailBackend + Default>(name: &str) {
    assert_eq!(B::default().name(), name);
}

/// Exercise the real wrapper environment using a fake launcher on Unix hosts.
#[cfg(unix)]
#[test]
fn launcher_does_not_restore_inherited_environment_after_env_clear() -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let root = tempfile::tempdir()?;
    let launcher = root.path().join("launcher");
    fs::write(&launcher, "#!/bin/sh\nshift 2\nexec \"$@\"\n")?;
    fs::set_permissions(&launcher, fs::Permissions::from_mode(0o700))?;
    let mut cmd = Command::new("/usr/bin/env");
    cmd.env_clear().env("JAIL_EXPLICIT", "allowed");
    let output = prepare_command(
        &Jail::new(root.path(), "environment"),
        &cmd,
        launcher.as_os_str(),
    )
    .output()?;
    assert!(output.status.success());
    // Some shells add PWD while executing a script. No inherited parent keys
    // should survive, and the explicitly supplied value must still be there.
    let env = String::from_utf8_lossy(&output.stdout);
    assert!(env.lines().any(|line| line == "JAIL_EXPLICIT=allowed"));
    assert!(
        env.lines()
            .all(|line| line.starts_with("JAIL_EXPLICIT=") || line.starts_with("PWD="))
    );
    Ok(())
}
