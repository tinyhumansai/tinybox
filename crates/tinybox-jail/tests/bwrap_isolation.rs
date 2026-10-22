//! Linux-only: a bubblewrap-jailed process is really isolated.
//!
//! Each test skips (with a note) when `bwrap` or unprivileged user namespaces
//! are missing, unless `TINYBOX_REQUIRE_BWRAP=1`, in which case a missing
//! sandbox is a failure. CI sets that variable so a skip can never pass for a
//! run. Every test that executes prints a `[bwrap-real]` line with its
//! duration for the CI log.
#![cfg(target_os = "linux")]

use std::io;
use std::net::TcpListener;
use std::path::Path;
use std::process::Command;
use std::time::Instant;

use tinybox_jail::{JailBackend, spawn_captured_with};

#[allow(dead_code)]
mod support;

use support::*;

#[test]
fn only_a_jail_with_a_private_network_is_suitable_for_untrusted_code() -> io::Result<()> {
    let Some(backend) = backend()? else {
        return Ok(());
    };
    let start = Instant::now();
    let root = tempfile::tempdir()?;
    // tinymcp's default configuration shares the host network: not suitable.
    assert!(!backend.is_suitable_for_untrusted_jail(&jail(root.path())));
    // The per-backend answer is the worst case, so it is never true.
    assert!(!backend.is_suitable_for_untrusted_code());
    // With a private network it is suitable, given `--disable-userns` support.
    let closed = jail(root.path()).deny_net();
    assert_eq!(
        backend.is_suitable_for_untrusted_jail(&closed),
        backend.isolation() >= tinybox_core::IsolationLevel::Process
    );
    done("suitability", start);
    Ok(())
}

#[test]
fn ungranted_paths_cannot_be_read() -> io::Result<()> {
    let Some(backend) = backend()? else {
        return Ok(());
    };
    let start = Instant::now();
    let root = tempfile::tempdir()?;
    let secret = tempfile::tempdir()?;
    let file = secret.path().join("secret");
    std::fs::write(&file, "token")?;
    let (ok, out) = sh(
        &backend,
        &jail(root.path()),
        &format!("cat '{}'", file.display()),
    )?;
    assert!(!ok && !out.contains("token"), "an ungranted file leaked");
    done("ungranted", start);
    Ok(())
}

#[test]
fn granted_paths_are_readable_and_root_is_writable() -> io::Result<()> {
    let Some(backend) = backend()? else {
        return Ok(());
    };
    let start = Instant::now();
    let root = tempfile::tempdir()?;
    let shared = tempfile::tempdir()?;
    std::fs::write(shared.path().join("f"), "hello")?;
    let j = jail(root.path()).add_read_only(shared.path());
    let script = format!(
        "cat '{}' && echo w > '{}' && ! echo w > '{}'",
        shared.path().join("f").display(),
        root.path().join("out").display(),
        shared.path().join("nope").display(),
    );
    let (ok, out) = sh(&backend, &j, &script)?;
    assert!(ok, "stdout: {out}");
    assert_eq!(out, "hello");
    assert_eq!(std::fs::read_to_string(root.path().join("out"))?, "w\n");
    done("granted", start);
    Ok(())
}

#[test]
fn a_read_only_grant_nested_in_the_root_stays_read_only() -> io::Result<()> {
    let Some(backend) = backend()? else {
        return Ok(());
    };
    let start = Instant::now();
    let root = tempfile::tempdir()?;
    let nested = root.path().join("vendor");
    std::fs::create_dir(&nested)?;
    std::fs::write(nested.join("lib"), "orig")?;
    // The read-only grant is declared; the jail's own root is writable.
    let j = jail(root.path()).add_read_only(&nested);
    let script = format!(
        "! echo evil > '{0}/lib' && ! touch '{0}/new' && echo ok > '{1}/free'",
        nested.display(),
        root.path().display()
    );
    let (ok, out) = sh(&backend, &j, &script)?;
    assert!(ok, "nested read-only grant was writable: {out}");
    assert_eq!(std::fs::read_to_string(nested.join("lib"))?, "orig");
    done("nested-ro", start);
    Ok(())
}

#[test]
fn a_read_only_grant_nested_in_a_read_write_grant_stays_read_only() -> io::Result<()> {
    let Some(backend) = backend()? else {
        return Ok(());
    };
    let start = Instant::now();
    let root = tempfile::tempdir()?;
    let rw = tempfile::tempdir()?;
    let nested = rw.path().join("sub").join("ro");
    std::fs::create_dir_all(&nested)?;
    let j = jail(root.path())
        .add_read_only(&nested)
        .add_read_write(rw.path());
    let script = format!(
        "! touch '{}/x' && touch '{}/y'",
        nested.display(),
        rw.path().display()
    );
    let (ok, _) = sh(&backend, &j, &script)?;
    assert!(ok);
    assert!(!nested.join("x").exists());
    done("nested-ro-in-rw", start);
    Ok(())
}

#[test]
fn grants_replacing_private_mounts_are_refused() -> io::Result<()> {
    let Some(backend) = backend()? else {
        return Ok(());
    };
    let start = Instant::now();
    let root = tempfile::tempdir()?;
    for bad in ["/", "/tmp", "/proc", "/dev"] {
        let j = jail(root.path()).add_read_only(bad);
        assert_eq!(
            refused(&backend, &j),
            Some(io::ErrorKind::InvalidInput),
            "{bad}"
        );
    }
    done("private-mount-grants", start);
    Ok(())
}

#[test]
fn dotdot_paths_cannot_slip_past_the_private_mount_guard() -> io::Result<()> {
    let Some(backend) = backend()? else {
        return Ok(());
    };
    let start = Instant::now();
    let root = tempfile::tempdir()?;
    for bad in ["/usr/../tmp", "/tmp/..", "/usr/../proc"] {
        // The trait method does not canonicalize first, so the backend itself
        // must refuse what is lexically `..`.
        let mut cmd = Command::new("/bin/true");
        cmd.arg("x");
        let err = backend
            .spawn_captured(&jail(root.path()).add_read_only(bad), cmd)
            .err()
            .map(|e| e.kind());
        assert_eq!(err, Some(io::ErrorKind::InvalidInput), "{bad}");
    }
    done("dotdot-grants", start);
    Ok(())
}

#[test]
fn a_symlink_planted_in_a_writable_root_cannot_redirect_a_nested_grant() -> io::Result<()> {
    let Some(backend) = backend()? else {
        return Ok(());
    };
    let start = Instant::now();
    let root = tempfile::tempdir()?;
    let secret = tempfile::tempdir()?;
    std::fs::write(secret.path().join("token"), "host-secret")?;
    // What a previous session's child could have left behind.
    std::os::unix::fs::symlink(secret.path(), root.path().join("vendor"))?;
    let j = jail(root.path()).add_read_only(root.path().join("vendor"));
    // Through the public API (canonicalizing) and through the trait directly.
    assert_eq!(refused(&backend, &j), Some(io::ErrorKind::InvalidInput));
    let mut cmd = Command::new("/bin/true");
    cmd.arg("x");
    let direct = backend.spawn_captured(&j, cmd).err().map(|e| e.kind());
    assert_eq!(direct, Some(io::ErrorKind::InvalidInput));
    done("planted-symlink", start);
    Ok(())
}

#[test]
fn deny_read_masks_a_file_inside_the_root() -> io::Result<()> {
    let Some(backend) = backend()? else {
        return Ok(());
    };
    let start = Instant::now();
    let root = tempfile::tempdir()?;
    let secret = root.path().join("secret");
    std::fs::write(&secret, "token")?;
    let mut j = jail(root.path());
    j.deny_read = vec![secret.clone()];
    let (_, out) = sh(&backend, &j, &format!("cat '{}'", secret.display()))?;
    assert!(!out.contains("token"), "denied file leaked: {out}");
    done("deny-file", start);
    Ok(())
}

#[test]
fn deny_read_of_a_missing_path_refuses_without_creating_a_host_mountpoint() -> io::Result<()> {
    let Some(backend) = backend()? else {
        return Ok(());
    };
    let start = Instant::now();
    let root = tempfile::tempdir()?;
    let denied = root.path().join(".ssh");
    let mut j = jail(root.path());
    j.deny_read = vec![denied.clone()];
    let cmd = Command::new("/bin/true");
    let error = match spawn_captured_with(&backend, &j, cmd) {
        Ok(mut child) => {
            let _ = child.wait()?;
            return Err(io::Error::other(format!(
                "missing deny_read path unexpectedly started a sandbox (host path exists: {})",
                denied.exists()
            )));
        }
        Err(error) => error,
    };
    assert_eq!(error.kind(), io::ErrorKind::NotFound);
    assert!(!denied.exists(), "preflight created the host deny path");
    std::fs::write(&denied, "host-file-can-still-be-created")?;
    assert_eq!(
        std::fs::read_to_string(&denied)?,
        "host-file-can-still-be-created"
    );
    done("deny-missing-refused-without-host-mutation", start);
    Ok(())
}

#[test]
fn deny_read_masks_a_runtime_directory() -> io::Result<()> {
    let Some(backend) = backend()? else {
        return Ok(());
    };
    let start = Instant::now();
    let root = tempfile::tempdir()?;
    let dir = root.path().join("run");
    std::fs::create_dir(&dir)?;
    std::fs::write(dir.join("socket-token"), "token")?;
    let mut j = jail(root.path());
    j.deny_read = vec![dir.clone()];
    let script = format!("ls '{0}'; cat '{0}/socket-token'", dir.display());
    let (_, out) = sh(&backend, &j, &script)?;
    assert!(
        !out.contains("socket-token") && !out.contains("token"),
        "{out}"
    );
    done("deny-dir", start);
    Ok(())
}

#[test]
fn deny_read_nested_in_a_writable_grant_is_refused() -> io::Result<()> {
    let Some(backend) = backend()? else {
        return Ok(());
    };
    let start = Instant::now();
    let root = tempfile::tempdir()?;
    let nested = root.path().join("a").join("secret");
    std::fs::create_dir_all(&nested)?;
    let mut j = jail(root.path());
    j.deny_read = vec![nested];
    assert_eq!(refused(&backend, &j), Some(io::ErrorKind::InvalidInput));
    done("deny-nested-refused", start);
    Ok(())
}

#[test]
fn deny_read_under_baseline_mounts_is_enforced() -> io::Result<()> {
    let Some(backend) = backend()? else {
        return Ok(());
    };
    let start = Instant::now();
    let root = tempfile::tempdir()?;
    let mut j = jail(root.path());
    let mut denied = vec![];
    for candidate in ["/etc/hosts", "/usr/lib/os-release"] {
        if Path::new(candidate).exists() {
            denied.push(candidate);
        }
    }
    j.deny_read = denied.iter().map(Into::into).collect();
    for path in &denied {
        let (_, out) = sh(&backend, &j, &format!("cat '{path}'"))?;
        assert!(out.is_empty(), "{path} leaked: {out}");
    }
    // The rest of the baseline still works.
    let (ok, _) = sh(&backend, &j, "ls /usr/bin >/dev/null")?;
    assert!(ok);
    done("deny-baseline", start);
    Ok(())
}

#[test]
fn host_processes_are_invisible() -> io::Result<()> {
    let Some(backend) = backend()? else {
        return Ok(());
    };
    let start = Instant::now();
    let root = tempfile::tempdir()?;
    let (ok, out) = sh(&backend, &jail(root.path()), "ls /proc | grep -c '^[0-9]'")?;
    assert!(ok);
    let visible: u32 = out.trim().parse().map_err(io::Error::other)?;
    assert!(visible <= 8, "only the jail's own processes: {visible}");
    done("pids", start);
    Ok(())
}

#[test]
fn network_is_unreachable_when_denied_and_reachable_when_shared() -> io::Result<()> {
    let Some(backend) = backend()? else {
        return Ok(());
    };
    if Command::new("bash").arg("-c").arg("true").status().is_err() {
        eprintln!("skipped: bash is needed for /dev/tcp");
        return Ok(());
    }
    let start = Instant::now();
    let root = tempfile::tempdir()?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let connect = format!("echo started; exec 3<>/dev/tcp/127.0.0.1/{port}");
    let mut cmd = Command::new("/usr/bin/env");
    cmd.args(["bash", "-c", &connect]);
    let (connected, _) = started(&run(&backend, &jail(root.path()).deny_net(), cmd)?)?;
    assert!(!connected, "connect must fail under deny_net");

    // Control: with the host network shared the same connect succeeds, which
    // is exactly the exposure `allow_net` carries.
    let mut cmd = Command::new("/usr/bin/env");
    cmd.args(["bash", "-c", &connect]);
    let (connected, _) = started(&run(&backend, &jail(root.path()), cmd)?)?;
    assert!(connected, "control connect should reach the host listener");
    done("network", start);
    Ok(())
}

#[test]
fn parent_environment_is_not_inherited_and_explicit_env_is_passed() -> io::Result<()> {
    let Some(backend) = backend()? else {
        return Ok(());
    };
    let start = Instant::now();
    let root = tempfile::tempdir()?;
    let mut cmd = Command::new("/bin/sh");
    cmd.arg("-c")
        .arg("printf %s \"$A-${HOME:-none}\"")
        .env("A", "1");
    let out = run(&backend, &jail(root.path()), cmd)?;
    assert_eq!(String::from_utf8_lossy(&out.stdout), "1-none");
    done("env", start);
    Ok(())
}

/// Waits until `pid` has exec'd `bwrap` (the launcher shell execs it), then
/// returns its raw `cmdline` and `environ`.
fn host_process_view(pid: u32) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let mut reached = false;
    for _ in 0..300 {
        let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default();
        if comm.trim() == "bwrap" {
            reached = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    if !reached {
        return Err(io::Error::other("the launcher never exec'd bwrap"));
    }
    Ok((
        std::fs::read(format!("/proc/{pid}/cmdline"))?,
        std::fs::read(format!("/proc/{pid}/environ"))?,
    ))
}

#[test]
fn credentials_never_appear_in_the_host_bwrap_cmdline_or_environment() -> io::Result<()> {
    let Some(backend) = backend()? else {
        return Ok(());
    };
    let start = Instant::now();
    let root = tempfile::tempdir()?;
    let mut cmd = Command::new("/bin/sleep");
    cmd.arg("5")
        .env("GITHUB_TOKEN", "ghp_integration_s3cret")
        .env("LD_PRELOAD", "/nonexistent/evil.so");
    let mut child = spawn_captured_with(&backend, &jail(root.path()).deny_net(), cmd)?;
    let (cmdline, environ) = host_process_view(child.id())?;
    let _ = child.kill();
    let _ = child.wait();
    for (name, bytes) in [("cmdline", cmdline), ("environ", environ)] {
        let text = String::from_utf8_lossy(&bytes);
        assert!(
            !text.contains("ghp_integration_s3cret") && !text.contains("evil.so"),
            "{name} of the host bwrap exposes the caller's env: {text:?}"
        );
    }
    done("host-cmdline-environ", start);
    Ok(())
}

#[test]
fn a_nul_byte_in_the_environment_cannot_inject_bwrap_options() -> io::Result<()> {
    let Some(backend) = backend()? else {
        return Ok(());
    };
    let start = Instant::now();
    let root = tempfile::tempdir()?;
    let host_file = tempfile::tempdir()?;
    let mut cmd = Command::new("/bin/true");
    // Without the check this would end the value early and make the rest a
    // further bwrap option: here, a bind of the host directory into the jail.
    let dir = host_file.path().display();
    cmd.env("K", format!("v\0--bind\0{dir}\0{dir}"));
    let err = spawn_captured_with(&backend, &jail(root.path()).deny_net(), cmd)
        .err()
        .map(|e| e.kind());
    assert_eq!(err, Some(io::ErrorKind::InvalidInput));
    done("nul-injection", start);
    Ok(())
}

#[test]
fn the_private_args_file_is_not_reachable_from_inside_the_sandbox() -> io::Result<()> {
    let Some(backend) = backend()? else {
        return Ok(());
    };
    let start = Instant::now();
    let root = tempfile::tempdir()?;
    let mut cmd = Command::new("/bin/sh");
    cmd.arg("-c")
        .arg("echo started; ls -l /proc/self/fd; ls /tmp")
        .env("GITHUB_TOKEN", "ghp_inside_s3cret");
    let (_, text) = started(&run(&backend, &jail(root.path()).deny_net(), cmd)?)?;
    assert!(
        !text.contains("tinybox-bwrap"),
        "args file reachable: {text}"
    );
    // The host's temp directory (where the file lived) is not the sandbox's.
    assert!(!text.contains("args"), "{text}");
    done("args-fd-closed", start);
    Ok(())
}

#[test]
fn ld_preload_in_the_caller_env_only_takes_effect_inside_the_sandbox() -> io::Result<()> {
    let Some(backend) = backend()? else {
        return Ok(());
    };
    let start = Instant::now();
    let root = tempfile::tempdir()?;
    let mut cmd = Command::new("/bin/true");
    cmd.env("LD_PRELOAD", "/nonexistent/tinybox-evil.so");
    let out = run(&backend, &jail(root.path()).deny_net(), cmd)?;
    // ld.so complains once per dynamic process that tries to preload. Exactly
    // one is the sandboxed `true`; a host-side bwrap or launcher that honoured
    // the variable would add more.
    let complaints = String::from_utf8_lossy(&out.stderr)
        .matches("cannot be preloaded")
        .count();
    assert_eq!(
        complaints,
        1,
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    done("ld-preload", start);
    Ok(())
}

#[test]
fn nested_user_namespaces_are_blocked_on_a_hardened_backend() -> io::Result<()> {
    let Some(backend) = backend()? else {
        return Ok(());
    };
    if backend.isolation() < tinybox_core::IsolationLevel::Process {
        // Only reachable on bubblewrap < 0.8; CI's bubblewrap has the flag.
        if std::env::var_os("TINYBOX_REQUIRE_BWRAP").is_some_and(|v| v == "1") {
            return Err(io::Error::other("bwrap lacks --disable-userns"));
        }
        eprintln!("skipped: bwrap lacks --disable-userns");
        return Ok(());
    }
    let start = Instant::now();
    let root = tempfile::tempdir()?;
    let (ok, _) = sh(&backend, &jail(root.path()).deny_net(), "unshare -U true")?;
    assert!(!ok, "a nested user namespace could be created");
    done("disable-userns", start);
    Ok(())
}
