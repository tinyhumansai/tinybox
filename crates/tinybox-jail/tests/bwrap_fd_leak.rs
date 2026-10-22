//! Descriptor-leak regressions live in their own process: they deliberately
//! hold inheritable descriptors open, which must not disturb the other
//! integration tests.
#![cfg(target_os = "linux")]

#[allow(dead_code)]
mod support;

use std::io;
use std::os::fd::AsRawFd;
use std::time::Instant;

use support::{backend, done, jail, sh};

#[test]
fn inheritable_host_descriptors_do_not_reach_the_sandbox() -> io::Result<()> {
    let Some(backend) = backend()? else {
        return Ok(());
    };
    let start = Instant::now();
    let root = tempfile::tempdir()?;
    let secret = tempfile::NamedTempFile::new()?;
    std::fs::write(secret.path(), "host-secret")?;
    // Simulate libraries that opened descriptors without O_CLOEXEC. Enough of
    // them that some are above 9, which a plain `sh` launcher cannot close.
    let mut files = Vec::new();
    for _ in 0..12 {
        let file = std::fs::File::open(secret.path())?;
        rustix::io::fcntl_setfd(&file, rustix::io::FdFlags::empty())?;
        files.push(file);
    }
    let fds: Vec<i32> = files.iter().map(AsRawFd::as_raw_fd).collect();
    assert!(fds.iter().any(|fd| *fd > 9), "{fds:?}");
    let mut script = String::new();
    for fd in &fds {
        script.push_str("cat /proc/self/fd/");
        script.push_str(&fd.to_string());
        script.push_str(" 2>/dev/null; ");
    }
    let (_, out) = sh(&backend, &jail(root.path()).deny_net(), &script)?;
    assert!(
        !out.contains("host-secret"),
        "descriptors {fds:?} leaked: {out}"
    );
    // The host's own descriptor is untouched.
    assert_eq!(files.len(), 12);
    done("fd-leak", start);
    Ok(())
}

#[test]
fn descriptors_opened_by_another_thread_during_the_spawn_do_not_leak() -> io::Result<()> {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    let Some(backend) = backend()? else {
        return Ok(());
    };
    let start = Instant::now();
    let root = tempfile::tempdir()?;
    let marker = root.path().join("leak-canary-file");
    std::fs::write(&marker, "x")?;
    let stop = Arc::new(AtomicBool::new(false));
    // A thread that keeps opening inheritable descriptors, the way a library
    // thread without O_CLOEXEC would, while sandboxes are being started.
    let opener = {
        let (stop, marker) = (Arc::clone(&stop), marker.clone());
        std::thread::spawn(move || -> io::Result<()> {
            while !stop.load(Ordering::Relaxed) {
                let file = std::fs::File::open(&marker)?;
                rustix::io::fcntl_setfd(&file, rustix::io::FdFlags::empty())?;
                std::thread::yield_now();
            }
            Ok(())
        })
    };
    let mut leaks = 0;
    for _ in 0..150 {
        let (_, out) = sh(
            &backend,
            &jail(root.path()).deny_net(),
            "ls -l /proc/self/fd | grep -c leak-canary-file",
        )?;
        leaks += out.trim().parse::<u32>().map_err(io::Error::other)?;
    }
    stop.store(true, Ordering::Relaxed);
    opener
        .join()
        .map_err(|_| io::Error::other("opener thread panicked"))??;
    assert_eq!(leaks, 0, "descriptors opened mid-spawn reached the sandbox");
    done("fd-race", start);
    Ok(())
}
