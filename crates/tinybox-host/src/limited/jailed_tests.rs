//! Native jail ownership regressions; providers are mocked without external services.
use super::*;
use std::result::Result;
use std::sync::Arc;
use tinybox_core::{ExecRequest, Host};

struct FixtureBackend;
impl tinybox_jail::JailBackend for FixtureBackend {
    fn name(&self) -> &'static str {
        "fixture"
    }
    fn is_available(&self) -> bool {
        true
    }
    fn spawn(
        &self,
        _: &tinybox_jail::Jail,
        mut command: std::process::Command,
    ) -> std::io::Result<std::process::Child> {
        command.spawn()
    }
}

#[tokio::test]
async fn jail_collection_caps_combined_output_and_drains_native_ownership()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let host = JailLocalHost::with_backend(
        tinybox_jail::Jail::new(root.path(), "fixture"),
        Arc::new(FixtureBackend),
        8,
    )?;
    let error = host
        .run(&ExecRequest::new([
            "/bin/sh",
            "-c",
            "printf 123456; printf 123456 >&2",
        ]))
        .await;
    assert!(matches!(
        error,
        Err(tinybox_core::Error::OutputLimitExceeded { limit: 8 })
    ));
    host.drain_checked().await?;
    assert!(!host.has_pending_cleanup());
    Ok(())
}

#[tokio::test]
async fn jail_collection_preserves_input_and_both_output_streams()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let host = JailLocalHost::with_backend(
        tinybox_jail::Jail::new(root.path(), "fixture"),
        Arc::new(FixtureBackend),
        64,
    )?;
    let mut request = ExecRequest::new(["/bin/sh", "-c", "cat; printf problem >&2"]);
    request.stdin = Some(b"input".to_vec());
    let output = host.run(&request).await?;
    assert_eq!(output.exit_code, 0);
    assert_eq!(output.stdout, b"input");
    assert_eq!(output.stderr, b"problem");
    host.drain_checked().await?;
    Ok(())
}

struct StartupBarrier {
    spawned: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<u32>>>,
    released: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
}
impl tinybox_jail::JailBackend for StartupBarrier {
    fn name(&self) -> &'static str {
        "startup-fixture"
    }
    fn is_available(&self) -> bool {
        true
    }
    fn spawn(
        &self,
        _: &tinybox_jail::Jail,
        mut command: std::process::Command,
    ) -> std::io::Result<std::process::Child> {
        let child = command.spawn()?;
        if let Some(sender) = self
            .spawned
            .lock()
            .map_err(|error| std::io::Error::other(error.to_string()))?
            .take()
        {
            let _ = sender.send(child.id());
        }
        let _ = self
            .released
            .lock()
            .map_err(|error| std::io::Error::other(error.to_string()))?
            .recv();
        Ok(child)
    }
}

#[tokio::test]
async fn dropped_jail_caller_during_startup_keeps_child_until_joined_cleanup()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let (spawned, started) = tokio::sync::oneshot::channel();
    let (release, released) = std::sync::mpsc::channel();
    let host = JailLocalHost::with_backend(
        tinybox_jail::Jail::new(root.path(), "fixture"),
        Arc::new(StartupBarrier {
            spawned: std::sync::Mutex::new(Some(spawned)),
            released: std::sync::Mutex::new(released),
        }),
        64,
    )?;
    let caller_host = host.clone();
    let caller = tokio::spawn(async move {
        caller_host
            .run(&ExecRequest::new(["/bin/sh", "-c", "sleep 600 & wait"]))
            .await
    });
    let pid = tokio::time::timeout(std::time::Duration::from_secs(5), started).await??;
    caller.abort();
    let cancelled = caller.await;
    assert!(cancelled.is_err());
    let drain_host = host.clone();
    let drain = tokio::spawn(async move { drain_host.drain_checked().await });
    tokio::task::yield_now().await;
    assert!(!drain.is_finished(), "startup still owns a live child");
    release.send(())?;
    tokio::time::timeout(std::time::Duration::from_secs(10), drain).await???;
    assert!(!host.has_pending_cleanup());
    #[cfg(target_os = "linux")]
    assert!(
        !std::path::Path::new(&format!("/proc/{pid}")).exists(),
        "direct child was not reaped"
    );
    #[cfg(not(target_os = "linux"))]
    let _ = pid;
    Ok(())
}

struct UnavailableBackend;
impl tinybox_jail::JailBackend for UnavailableBackend {
    fn name(&self) -> &'static str {
        "unavailable-fixture"
    }
    fn is_available(&self) -> bool {
        false
    }
    fn spawn(
        &self,
        _: &tinybox_jail::Jail,
        _: std::process::Command,
    ) -> std::io::Result<std::process::Child> {
        Err(std::io::Error::other("unavailable backend must not spawn"))
    }
}
#[test]
fn unavailable_jail_provider_refuses_instead_of_selecting_another_backend()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let result = JailLocalHost::with_backend(
        tinybox_jail::Jail::new(root.path(), "fixture"),
        Arc::new(UnavailableBackend),
        64,
    );
    assert!(matches!(result, Err(error) if error.kind() == std::io::ErrorKind::Unsupported));
    Ok(())
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn detected_landlock_collection_enforces_writable_root()
-> Result<(), Box<dyn std::error::Error>> {
    let backend = tinybox_jail::default_backend();
    if backend.name() != "landlock" || !backend.is_available() {
        return Ok(()); // Other platforms/kernels exercise explicit unavailable fixtures.
    }
    let root = tempfile::tempdir()?;
    let outside = tempfile::tempdir()?;
    let forbidden = outside.path().join("forbidden");
    let host = JailLocalHost::new(
        tinybox_jail::Jail::new(root.path(), "confinement-fixture"),
        1024,
    )?;
    let script = format!(
        "printf allowed > allowed; printf denied > '{}'",
        forbidden.display()
    );
    let mut request = ExecRequest::new(["/bin/sh", "-c", script.as_str()]);
    request.cwd = Some(root.path().to_owned());
    let output = host.run(&request).await?;
    assert_ne!(output.exit_code, 0);
    assert_eq!(std::fs::read(root.path().join("allowed"))?, b"allowed");
    assert!(!forbidden.exists());
    host.drain_checked().await?;
    Ok(())
}

#[tokio::test]
async fn retained_jail_cleanup_retries_and_releases_native_child()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::process::CommandExt;
    let root = tempfile::tempdir()?;
    let host = JailLocalHost::with_backend(
        tinybox_jail::Jail::new(root.path(), "retry-fixture"),
        Arc::new(FixtureBackend),
        64,
    )?;
    let mut command = std::process::Command::new("/bin/sh");
    command.args(["-c", "sleep 600 & wait"]).process_group(0);
    let child = command.spawn()?;
    let pid = child.id();
    let group = i32::try_from(pid)?;
    let retained = retain_cleanup(
        &host.state,
        child,
        group,
        Err(failure(
            "kill jail group",
            "fixture transient failure".into(),
        )),
    );
    assert!(retained.is_err());
    assert!(host.has_pending_cleanup());
    host.drain_checked().await?;
    assert!(!host.has_pending_cleanup());
    #[cfg(target_os = "linux")]
    assert!(!std::path::Path::new(&format!("/proc/{pid}")).exists());
    host.drain_checked().await?;
    Ok(())
}

#[test]
fn jail_execution_without_a_runtime_fails_before_native_start()
-> Result<(), Box<dyn std::error::Error>> {
    use std::future::Future;
    let root = tempfile::tempdir()?;
    let host = JailLocalHost::with_backend(
        tinybox_jail::Jail::new(root.path(), "runtime-fixture"),
        Arc::new(FixtureBackend),
        64,
    )?;
    let request = ExecRequest::new(["/bin/sh", "-c", "exit 0"]);
    let mut future = Box::pin(host.run(&request));
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(matches!(
        future.as_mut().poll(&mut context),
        std::task::Poll::Ready(Err(_))
    ));
    assert!(!host.has_pending_cleanup());
    Ok(())
}

#[tokio::test]
async fn jail_receives_only_the_explicitly_supplied_environment()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let host = JailLocalHost::with_backend(
        tinybox_jail::Jail::new(root.path(), "env-fixture"),
        Arc::new(FixtureBackend),
        64,
    )?;
    let mut request = ExecRequest::new([
        "/bin/sh",
        "-c",
        "printf '%s|%s' \"${HOME-missing}\" \"$JAIL_GRANTED\"",
    ]);
    request.env.insert("JAIL_GRANTED".into(), "granted".into());
    let output = host.run(&request).await?;
    assert_eq!(output.stdout, b"missing|granted");
    assert_eq!(output.exit_code, 0);
    Ok(())
}

#[tokio::test]
async fn failed_jail_startup_releases_supervisor_admission()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let host = JailLocalHost::with_backend(
        tinybox_jail::Jail::new(root.path().join("absent"), "startup-failure-fixture"),
        Arc::new(FixtureBackend),
        64,
    )?;
    let result = host
        .run(&ExecRequest::new(["/bin/sh", "-c", "exit 0"]))
        .await;
    assert!(result.is_err());
    host.drain_checked().await?;
    assert!(!host.has_pending_cleanup());
    Ok(())
}

#[test]
fn jailed_host_debug_excludes_workspace_and_label() -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let host = JailLocalHost::with_backend(
        tinybox_jail::Jail::new(root.path(), "PRIVATE_LABEL_SENTINEL"),
        Arc::new(FixtureBackend),
        64,
    )?;
    let debug = format!("{host:?}");
    assert!(debug.contains("fixture"));
    assert!(!debug.contains("PRIVATE_LABEL_SENTINEL"));
    assert!(!debug.contains(root.path().to_string_lossy().as_ref()));
    assert_eq!(host.name(), crate::LOCAL);
    Ok(())
}

struct CountedBackend(Arc<std::sync::atomic::AtomicUsize>);
impl tinybox_jail::JailBackend for CountedBackend {
    fn name(&self) -> &'static str {
        "counted-fixture"
    }
    fn is_available(&self) -> bool {
        true
    }
    fn spawn(
        &self,
        _: &tinybox_jail::Jail,
        _: std::process::Command,
    ) -> std::io::Result<std::process::Child> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Err(std::io::Error::other(
            "cancelled admission must not start native work",
        ))
    }
}
#[tokio::test(flavor = "current_thread")]
async fn dropping_jail_call_before_supervisor_start_does_not_spawn()
-> Result<(), Box<dyn std::error::Error>> {
    use std::future::Future;
    let root = tempfile::tempdir()?;
    let starts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let host = JailLocalHost::with_backend(
        tinybox_jail::Jail::new(root.path(), "cancelled-admission"),
        Arc::new(CountedBackend(starts.clone())),
        64,
    )?;
    let request = ExecRequest::new(["/bin/sh", "-c", "exit 0"]);
    let mut future = Box::pin(host.run(&request));
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(future.as_mut().poll(&mut context).is_pending());
    drop(future);
    host.drain_checked().await?;
    assert_eq!(starts.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert!(!host.has_pending_cleanup());
    Ok(())
}

#[test]
fn jail_supervisor_fault_retains_child_for_cleanup_acknowledgement()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let host = JailLocalHost::with_backend(
        tinybox_jail::Jail::new(root.path(), "runtime-fault-fixture"),
        Arc::new(FixtureBackend),
        64,
    )?;
    // Pipe registration panics without an I/O driver after native startup.
    let missing_io = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()?;
    let result =
        missing_io.block_on(host.run(&ExecRequest::new(["/bin/sh", "-c", "sleep 600 & wait"])));
    assert!(result.is_err());
    assert!(
        host.has_pending_cleanup(),
        "a supervisor fault must keep native ownership"
    );
    drop(missing_io);
    let recovery = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    recovery.block_on(host.drain_checked())?;
    assert!(!host.has_pending_cleanup());
    Ok(())
}

struct MissingOutputBackend;
impl tinybox_jail::JailBackend for MissingOutputBackend {
    fn name(&self) -> &'static str {
        "missing-output"
    }
    fn is_available(&self) -> bool {
        true
    }
    fn spawn(
        &self,
        _: &Jail,
        mut command: std::process::Command,
    ) -> std::io::Result<std::process::Child> {
        command.spawn()
    }
    fn spawn_captured(
        &self,
        _: &Jail,
        mut command: std::process::Command,
    ) -> std::io::Result<std::process::Child> {
        command.stdout(std::process::Stdio::null()).spawn()
    }
}

#[tokio::test]
async fn malformed_provider_output_still_cleans_native_child()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let host = JailLocalHost::with_backend(
        Jail::new(root.path(), "fixture"),
        Arc::new(MissingOutputBackend),
        64,
    )?;
    let error = host
        .run(&ExecRequest::new(["/bin/sh", "-c", "exec sleep 60"]))
        .await;
    assert!(matches!(
        error,
        Err(Error::Backend {
            operation: "collect output",
            ..
        })
    ));
    host.drain_checked().await?;
    assert!(!host.has_pending_cleanup());
    assert_eq!(host.state.active.load(Ordering::SeqCst), 0);
    Ok(())
}

struct PanickingStartup;
impl tinybox_jail::JailBackend for PanickingStartup {
    fn name(&self) -> &'static str {
        "panicking-startup"
    }
    fn is_available(&self) -> bool {
        true
    }
    // Deliberate provider panic verifies the supervisor fault boundary.
    #[allow(clippy::panic)]
    fn spawn(&self, _: &Jail, _: std::process::Command) -> std::io::Result<std::process::Child> {
        panic!("fixture provider fault before native creation");
    }
}

#[tokio::test]
async fn provider_startup_fault_releases_native_supervisor_admission()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let host = JailLocalHost::with_backend(
        Jail::new(root.path(), "fixture"),
        Arc::new(PanickingStartup),
        64,
    )?;
    let error = host.run(&ExecRequest::new(["/bin/sh", "-c", "true"])).await;
    assert!(matches!(
        error,
        Err(Error::Backend {
            operation: "start native jail",
            ..
        })
    ));
    host.drain_checked().await?;
    assert!(!host.has_pending_cleanup());
    assert_eq!(host.state.active.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn observed_jail_cancellation_joins_native_supervisor()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let host = JailLocalHost::with_backend(
        Jail::new(root.path(), "fixture"),
        Arc::new(FixtureBackend),
        64,
    )?;
    let (observer, received) = super::super::observed_tests::Observer::with_first();
    let runner = host.clone();
    let events = observer.clone();
    let task = tokio::spawn(async move {
        runner
            .run_observed(
                &ExecRequest::new(["/bin/sh", "-c", "printf ready; exec sleep 600"]),
                events,
            )
            .await
    });
    let first = tokio::time::timeout(std::time::Duration::from_secs(5), received).await;
    observer.cancel();
    let outcome = task.await?;
    assert!(first.is_ok_and(|first| first.is_ok()));
    assert!(outcome.is_err());
    assert_eq!(host.state.active.load(Ordering::SeqCst), 0);
    assert!(!host.has_pending_cleanup());
    Ok(())
}
