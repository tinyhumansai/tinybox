//! Native jail ownership regressions; providers are mocked without external services.
use super::*;

#[cfg(target_os = "linux")]
#[test]
fn cpu_throttling_counter_requires_one_well_formed_nr_throttled_value() {
    assert_eq!(
        parse_cpu_throttled_counter("usage_usec 12\nnr_throttled 0\n"),
        Some(0)
    );
    assert_eq!(parse_cpu_throttled_counter("nr_throttled 3\n"), Some(3));
    assert_eq!(parse_cpu_throttled_counter("nr_throttled nope\n"), None);
    assert_eq!(
        parse_cpu_throttled_counter("nr_throttled 1\nnr_throttled 2\n"),
        None
    );
    assert_eq!(parse_cpu_throttled_counter("usage_usec 12\n"), None);
}

#[cfg(target_os = "linux")]
#[test]
fn cpu_event_report_rejects_custom_paths_and_accepts_masked_run_paths()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let custom_runtime = tempfile::tempdir()?;
    std::fs::set_permissions(
        custom_runtime.path(),
        std::fs::Permissions::from_mode(0o700),
    )?;
    let mut command = std::process::Command::new("systemd-run");
    command.args([
        "--scope",
        "--unit=tinybox-native-fixture.scope",
        "--property=CPUQuota=10%",
        "--tmpfs",
        "/run",
        "--tmpfs",
        "/sys",
        "--clearenv",
    ]);
    let mut env = BTreeMap::new();
    assert!(CpuEventReport::prepare_in(&command, &mut env, custom_runtime.path()).is_none());
    assert!(
        env.is_empty(),
        "unmasked runtime paths must not be handed off"
    );

    let Some(runtime_root) = std::env::var_os("XDG_RUNTIME_DIR").map(std::path::PathBuf::from)
    else {
        return Ok(());
    };
    let Ok(metadata) = std::fs::metadata(&runtime_root) else {
        return Ok(());
    };
    if !runtime_root.starts_with("/run/")
        || metadata.uid() != std::fs::metadata("/proc/self")?.uid()
        || metadata.mode() & 0o077 != 0
    {
        return Ok(());
    }
    let runtime = tempfile::Builder::new()
        .prefix("tinybox-test-")
        .tempdir_in(runtime_root)?;
    std::fs::set_permissions(runtime.path(), std::fs::Permissions::from_mode(0o700))?;
    let report = CpuEventReport::prepare_in(&command, &mut env, runtime.path())
        .ok_or("masked /run runtime path did not get a report")?;
    let report_path = env
        .get(CPU_EVENT_FILE_ENV)
        .ok_or("report path was not passed to the trusted wrapper")?;
    assert_eq!(std::fs::read_to_string(report_path)?, "nr_throttled 0\n");
    drop(report);
    assert!(!std::path::Path::new(report_path).exists());
    env.clear();

    let mut unmetered = std::process::Command::new("systemd-run");
    unmetered.args([
        "--scope",
        "--unit=tinybox-native-fixture.scope",
        "--tmpfs",
        "/run",
        "--tmpfs",
        "/sys",
    ]);
    assert!(CpuEventReport::prepare_in(&unmetered, &mut env, custom_runtime.path()).is_none());
    assert!(env.is_empty());
    Ok(())
}
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

#[test]
fn jailed_local_host_reports_local_execution_location() -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let host = JailLocalHost::with_backend(
        tinybox_jail::Jail::new(root.path(), "execution-location"),
        Arc::new(FixtureBackend),
        64,
    )?;

    assert_eq!(
        host.execution_location(),
        tinybox_core::HostExecutionLocation::Local
    );
    Ok(())
}

#[cfg(unix)]
struct MissingStdinBackend;
#[cfg(unix)]
impl tinybox_jail::JailBackend for MissingStdinBackend {
    fn name(&self) -> &'static str {
        "missing-stdin-fixture"
    }
    fn is_available(&self) -> bool {
        true
    }
    fn spawn(
        &self,
        _: &tinybox_jail::Jail,
        _: std::process::Command,
    ) -> std::io::Result<std::process::Child> {
        Err(std::io::Error::other("owned spawn expected"))
    }
    fn spawn_owned_captured(
        &self,
        _: &tinybox_jail::Jail,
        mut command: std::process::Command,
    ) -> std::io::Result<tinybox_jail::OwnedChild> {
        command
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        tinybox_jail::OwnedChild::from_std(command.spawn()?)
    }
}

#[cfg(unix)]
#[tokio::test]
async fn supplied_payload_is_rejected_when_owned_child_has_no_stdin()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let host = JailLocalHost::with_backend(
        tinybox_jail::Jail::new(root.path(), "missing-stdin"),
        Arc::new(MissingStdinBackend),
        64,
    )?;
    let mut request = ExecRequest::new(["/bin/sh", "-c", "cat; printf completed"]);
    request.stdin = Some(b"payload".to_vec());

    let result = host.run(&request).await;
    assert!(
        result.is_err(),
        "a supplied payload must not be silently lost"
    );
    host.drain_checked().await?;
    assert!(!host.has_pending_cleanup());
    Ok(())
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

#[cfg(target_os = "windows")]
#[tokio::test]
async fn detected_owned_backend_runs_with_only_the_approved_environment()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let host = JailLocalHost::new(
        tinybox_jail::Jail::new(root.path(), "host-owned-appcontainer"),
        1024,
    )?;
    assert!(format!("{host:?}").contains("appcontainer"));

    let parent_path = std::env::var("PATH").ok();
    let mut request = ExecRequest::new(["cmd.exe", "/C", "echo %TINYBOX_APPROVED_ENV%|%PATH%"]);
    request.cwd = Some(root.path().to_owned());
    request.env.insert(
        "TINYBOX_APPROVED_ENV".to_owned(),
        "approved-marker".to_owned(),
    );
    let output = host.run(&request).await?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("approved-marker"));
    if let Some(parent_path) = parent_path {
        assert!(
            !stdout.contains(&parent_path),
            "parent PATH leaked into jailed process"
        );
    }
    host.drain_checked().await?;
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
        tinybox_jail::OwnedChild::from_std(child)?.with_local_process_group_id(pid),
        Some(group),
        Err(failure(
            "kill jail group",
            "fixture transient failure".into(),
        )),
    );
    assert!(retained.is_err());
    assert!(host.has_pending_cleanup());
    assert!(host.has_pending_observed_cleanup());
    host.retry_observed_cleanup().await?;
    assert!(!host.has_pending_observed_cleanup());
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

#[cfg(unix)]
struct UnidentifiedProcess {
    child: std::process::Child,
    reported_id: Option<u32>,
    terminated: Arc<std::sync::atomic::AtomicBool>,
    report_termination_error_after_stop: bool,
    fail_termination: Arc<std::sync::atomic::AtomicBool>,
    skip_next_termination: Arc<std::sync::atomic::AtomicBool>,
}
#[cfg(unix)]
impl tinybox_jail::OwnedProcess for UnidentifiedProcess {
    fn id(&self) -> Option<u32> {
        self.reported_id
    }
    fn try_wait(&mut self) -> std::io::Result<Option<tinybox_jail::ChildStatus>> {
        self.child
            .try_wait()
            .map(|status| status.map(|status| tinybox_jail::ChildStatus::from_code(status.code())))
    }
    fn terminate(&mut self) -> std::io::Result<()> {
        self.terminated
            .store(true, std::sync::atomic::Ordering::SeqCst);
        if self
            .fail_termination
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(std::io::Error::other("termination temporarily unavailable"));
        }
        if self
            .skip_next_termination
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Ok(());
        }
        self.child.kill()?;
        if self.report_termination_error_after_stop {
            let _ = self.child.wait()?;
            Err(std::io::Error::other("child exited during termination"))
        } else {
            Ok(())
        }
    }
}

#[cfg(unix)]
struct UnidentifiedBackend {
    reported_id: Option<u32>,
    local_group: Option<u32>,
    terminated: Arc<std::sync::atomic::AtomicBool>,
    report_termination_error_after_stop: bool,
    fail_termination: Arc<std::sync::atomic::AtomicBool>,
    skip_next_termination: Arc<std::sync::atomic::AtomicBool>,
}
#[cfg(unix)]
impl tinybox_jail::JailBackend for UnidentifiedBackend {
    fn name(&self) -> &'static str {
        "unidentified-fixture"
    }
    fn is_available(&self) -> bool {
        true
    }
    fn spawn(
        &self,
        _: &tinybox_jail::Jail,
        _: std::process::Command,
    ) -> std::io::Result<std::process::Child> {
        Err(std::io::Error::other("owned spawn expected"))
    }
    fn spawn_owned_captured(
        &self,
        _: &tinybox_jail::Jail,
        mut command: std::process::Command,
    ) -> std::io::Result<tinybox_jail::OwnedChild> {
        let child = command.spawn()?;
        let owned = tinybox_jail::OwnedChild::new(
            UnidentifiedProcess {
                child,
                reported_id: self.reported_id,
                terminated: self.terminated.clone(),
                report_termination_error_after_stop: self.report_termination_error_after_stop,
                fail_termination: self.fail_termination.clone(),
                skip_next_termination: self.skip_next_termination.clone(),
            },
            None,
            None,
            None,
        );
        Ok(match self.local_group {
            Some(group) => owned.with_local_process_group_id(group),
            None => owned,
        })
    }
}

#[cfg(unix)]
#[tokio::test]
async fn owned_child_without_native_id_is_cleaned_when_pipe_capture_fails()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let terminated = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let host = JailLocalHost::with_backend(
        tinybox_jail::Jail::new(root.path(), "unidentified-child"),
        Arc::new(UnidentifiedBackend {
            reported_id: None,
            local_group: None,
            terminated: terminated.clone(),
            report_termination_error_after_stop: false,
            fail_termination: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            skip_next_termination: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }),
        64,
    )?;

    let Err(error) = host
        .run(&ExecRequest::new(["/bin/sh", "-c", "sleep 30"]))
        .await
    else {
        return Err("missing captured pipes should fail collection".into());
    };
    assert!(error.to_string().contains("missing stdout pipe"));
    assert!(
        terminated.load(std::sync::atomic::Ordering::SeqCst),
        "the backend-owned child must be stopped before its handle is dropped"
    );
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn unrepresentable_local_group_id_is_terminated_before_error()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let terminated = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let host = JailLocalHost::with_backend(
        tinybox_jail::Jail::new(root.path(), "unrepresentable-child-id"),
        Arc::new(UnidentifiedBackend {
            reported_id: Some(u32::MAX),
            local_group: Some(u32::MAX),
            terminated: terminated.clone(),
            report_termination_error_after_stop: true,
            fail_termination: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            skip_next_termination: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }),
        64,
    )?;

    let Err(error) = host
        .run(&ExecRequest::new(["/bin/sh", "-c", "sleep 30"]))
        .await
    else {
        return Err("an unrepresentable verified process group must be refused".into());
    };
    assert!(matches!(
        error,
        tinybox_core::Error::Backend {
            operation: "identify jail child",
            ..
        }
    ));
    assert!(
        terminated.load(std::sync::atomic::Ordering::SeqCst),
        "the child must be stopped even when its process-group id cannot be represented"
    );
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn unidentified_child_is_retained_when_termination_fails_while_running()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let terminated = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let fail_termination = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let host = JailLocalHost::with_backend(
        tinybox_jail::Jail::new(root.path(), "unidentified-child-retry"),
        Arc::new(UnidentifiedBackend {
            reported_id: None,
            local_group: None,
            terminated,
            report_termination_error_after_stop: false,
            fail_termination: fail_termination.clone(),
            skip_next_termination: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }),
        64,
    )?;

    let Err(error) = host
        .run(&ExecRequest::new(["/bin/sh", "-c", "sleep 30"]))
        .await
    else {
        return Err("a backend child without an id cannot be supervised".into());
    };
    assert!(
        error
            .to_string()
            .contains("termination temporarily unavailable")
    );
    assert!(
        host.has_pending_cleanup(),
        "failed termination must retain the unidentified child for retry"
    );

    fail_termination.store(false, std::sync::atomic::Ordering::SeqCst);
    host.drain_checked().await?;
    assert!(!host.has_pending_cleanup());
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn zero_process_group_id_is_rejected_before_cleanup_can_signal_group_zero()
-> Result<(), Box<dyn std::error::Error>> {
    let child = std::process::Command::new("sleep").arg("30").spawn()?;
    let mut child = tinybox_jail::OwnedChild::new(
        UnidentifiedProcess {
            child,
            reported_id: Some(0),
            terminated: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            report_termination_error_after_stop: false,
            fail_termination: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            skip_next_termination: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        },
        None,
        None,
        None,
    )
    .with_local_process_group_id(0);

    let result = verified_local_process_group_id(&mut child).await;
    if result.is_ok() {
        child.terminate()?;
        let _ = child.try_wait()?;
    }
    assert!(result.is_err(), "process-group zero is not a child group");
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn generic_owned_process_id_is_not_treated_as_a_local_process_group()
-> Result<(), Box<dyn std::error::Error>> {
    let child = std::process::Command::new("sleep").arg("30").spawn()?;
    let reported_id = child.id();
    let mut child = tinybox_jail::OwnedChild::new(
        UnidentifiedProcess {
            child,
            reported_id: Some(reported_id),
            terminated: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            report_termination_error_after_stop: false,
            fail_termination: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            skip_next_termination: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        },
        None,
        None,
        None,
    );

    assert_eq!(child.id(), Some(reported_id));
    assert_eq!(verified_local_process_group_id(&mut child).await?, None);
    terminate(&mut child, None).await?;
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn owned_termination_runs_even_when_group_kill_is_denied()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::process::CommandExt;

    let mut command = std::process::Command::new("sleep");
    command.arg("30").process_group(0);
    let child = command.spawn()?;
    let group = i32::try_from(child.id())?;
    let terminated = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut child = tinybox_jail::OwnedChild::new(
        UnidentifiedProcess {
            child,
            reported_id: Some(u32::try_from(group)?),
            terminated: terminated.clone(),
            report_termination_error_after_stop: false,
            fail_termination: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            skip_next_termination: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        },
        None,
        None,
        None,
    );
    let result = terminate_with_group_ops(&mut child, group, |_| Err(nix::errno::Errno::EPERM), {
        let terminated = terminated.clone();
        move |_| {
            let terminated = terminated.clone();
            async move { Ok(!terminated.load(std::sync::atomic::Ordering::SeqCst)) }
        }
    })
    .await;
    if result.is_err() {
        child.terminate()?;
        let _ = wait_child(&mut child).await?;
    }

    assert!(
        terminated.load(std::sync::atomic::Ordering::SeqCst),
        "the owned process must be asked to terminate after group signaling fails"
    );
    assert!(result.is_ok(), "the owner terminated the remaining group");
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn unidentified_child_reap_wait_uses_a_bounded_cleanup_deadline()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let host = JailLocalHost::with_backend(
        tinybox_jail::Jail::new(root.path(), "unidentified-child-timeout"),
        Arc::new(FixtureBackend),
        64,
    )?;
    let child = std::process::Command::new("sleep").arg("30").spawn()?;
    let skip_next_termination = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let child = tinybox_jail::OwnedChild::new(
        UnidentifiedProcess {
            child,
            reported_id: None,
            terminated: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            report_termination_error_after_stop: false,
            fail_termination: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            skip_next_termination: skip_next_termination.clone(),
        },
        None,
        None,
        None,
    );
    let mut retained = RetainedOnDrop {
        child: Some(child),
        group: None,
        state: host.state.clone(),
    };

    let Some(child) = retained.child.as_mut() else {
        return Err("retained test child is absent".into());
    };
    let result =
        terminate_unidentified_child_with_timeout(child, std::time::Duration::from_millis(20))
            .await;
    assert!(
        result.is_err(),
        "the cleanup helper must enforce its deadline and return a retained-child error"
    );
    assert!(
        !skip_next_termination.load(std::sync::atomic::Ordering::SeqCst),
        "the test child ignored the first termination request"
    );
    drop(retained);
    assert!(
        host.has_pending_cleanup(),
        "timeout must preserve ownership"
    );
    host.drain_checked().await?;
    assert!(!host.has_pending_cleanup());
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
#[cfg(target_os = "macos")]
fn jail_supervisor_fault_retains_child_for_cleanup_acknowledgement()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let host = JailLocalHost::with_backend(
        tinybox_jail::Jail::new(root.path(), "runtime-fault-fixture"),
        Arc::new(FixtureBackend),
        64,
    )?;
    // Simulate a supervisor panic after native startup and prove the owned
    // child remains available to the normal cleanup acknowledgement path.
    let missing_timer = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()?;
    let result =
        missing_timer.block_on(host.run(&ExecRequest::new(["/bin/sh", "-c", "sleep 600 & wait"])));
    assert!(result.is_err());
    assert!(
        host.has_pending_cleanup(),
        "native ownership survives the panic"
    );
    drop(missing_timer);
    let recovery = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    recovery.block_on(host.drain_checked())?;
    assert!(!host.has_pending_cleanup());
    Ok(())
}

#[test]
fn owned_file_pipes_collect_streams_and_exit_status() -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let host = JailLocalHost::with_backend(
        tinybox_jail::Jail::new(root.path(), "owned-pipe-fixture"),
        Arc::new(FixtureBackend),
        64,
    )?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let output = runtime.block_on(host.run(&ExecRequest::new([
        "/bin/sh",
        "-c",
        "printf owned-pipes; printf owned-error >&2; exit 23",
    ])))?;
    assert_eq!(output.stdout, b"owned-pipes");
    assert_eq!(output.stderr, b"owned-error");
    assert_eq!(output.exit_code, 23);
    runtime.block_on(host.drain_checked())?;
    assert!(!host.has_pending_cleanup());
    Ok(())
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "current_thread")]
async fn cancelling_a_pipe_read_releases_its_descriptor() -> Result<(), Box<dyn std::error::Error>>
{
    use std::{os::fd::AsRawFd, path::PathBuf};

    let (reader, writer) = nix::unistd::pipe()?;
    let reader = std::fs::File::from(reader);
    let raw_reader = reader.as_raw_fd();
    let descriptor = PathBuf::from(format!("/proc/self/fd/{raw_reader}"));
    let pipe_identity = std::fs::read_link(&descriptor)?;
    let mut reader = async_pipe(reader)?;
    let (started, waiting) = oneshot::channel();
    let task = tokio::spawn(async move {
        let mut buffer = [0; 1];
        let mut read = Box::pin(tokio::io::AsyncReadExt::read(&mut reader, &mut buffer));
        let mut started = Some(started);
        std::future::poll_fn(|cx| {
            let result = std::future::Future::poll(read.as_mut(), cx);
            if result.is_pending()
                && let Some(started) = started.take()
            {
                let _ = started.send(());
            }
            result
        })
        .await
    });

    // Confirm the pending read was polled while the writer is held open.
    waiting.await?;
    task.abort();
    let _ = task.await;
    drop(writer);
    let descriptor_reused =
        std::fs::read_link(&descriptor).map_or(true, |target| target != pipe_identity);

    assert!(
        descriptor_reused,
        "cancelling a read must release descriptor {raw_reader}"
    );
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn async_pipe_round_trips_bytes_through_flush_and_shutdown()
-> Result<(), Box<dyn std::error::Error>> {
    let (reader, writer) = nix::unistd::pipe()?;
    let mut reader = async_pipe(std::fs::File::from(reader))?;
    let mut writer = async_pipe(std::fs::File::from(writer))?;
    tokio::io::AsyncWriteExt::write_all(&mut writer, b"pipe").await?;
    tokio::io::AsyncWriteExt::flush(&mut writer).await?;
    tokio::io::AsyncWriteExt::shutdown(&mut writer).await?;

    let mut output = [0; 4];
    tokio::io::AsyncReadExt::read_exact(&mut reader, &mut output).await?;
    assert_eq!(&output, b"pipe");
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn async_pipe_write_resumes_after_backpressure_clears()
-> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;

    let (reader, writer) = nix::unistd::pipe()?;
    let mut writer = std::fs::File::from(writer);
    let flags = nix::fcntl::fcntl(&writer, nix::fcntl::FcntlArg::F_GETFL)?;
    nix::fcntl::fcntl(
        &writer,
        nix::fcntl::FcntlArg::F_SETFL(
            nix::fcntl::OFlag::from_bits_retain(flags) | nix::fcntl::OFlag::O_NONBLOCK,
        ),
    )?;
    let fill = [0; 4096];
    loop {
        match writer.write(&fill) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) => return Err(error.into()),
        }
    }

    let mut writer = async_pipe(writer)?;
    let mut reader = async_pipe(std::fs::File::from(reader))?;
    let (started, waiting) = oneshot::channel();
    let write = tokio::spawn(async move {
        let mut write = Box::pin(tokio::io::AsyncWriteExt::write(&mut writer, b"x"));
        let mut started = Some(started);
        std::future::poll_fn(|cx| {
            let result = std::future::Future::poll(write.as_mut(), cx);
            if result.is_pending()
                && let Some(started) = started.take()
            {
                let _ = started.send(());
            }
            result
        })
        .await
    });
    waiting.await?;

    let mut drained = [0; 8192];
    assert_ne!(
        tokio::io::AsyncReadExt::read(&mut reader, &mut drained).await?,
        0
    );
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(5), write).await???,
        1
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn async_pipe_propagates_a_get_flags_failure() -> Result<(), Box<dyn std::error::Error>> {
    let (reader, writer) = nix::unistd::pipe()?;
    let reader = std::fs::File::from(reader);
    let result = set_nonblocking_with(&reader, |_, _| Err(nix::errno::Errno::EBADF));
    assert!(result.is_err());
    drop(writer);
    Ok(())
}

#[cfg(unix)]
#[test]
fn async_pipe_propagates_a_set_flags_failure() -> Result<(), Box<dyn std::error::Error>> {
    let (reader, writer) = nix::unistd::pipe()?;
    let reader = std::fs::File::from(reader);
    let mut calls = 0;
    let result = set_nonblocking_with(&reader, |_, _| {
        calls += 1;
        if calls == 1 {
            Ok(0)
        } else {
            Err(nix::errno::Errno::EBADF)
        }
    });
    assert!(result.is_err());
    drop(writer);
    Ok(())
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn async_pipe_rejects_a_regular_file_epoll_cannot_watch()
-> Result<(), Box<dyn std::error::Error>> {
    let file = tempfile::tempfile()?;
    assert!(async_pipe(file).is_err());
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn async_pipe_reports_nonblocking_setup_failure() -> Result<(), Box<dyn std::error::Error>> {
    let descriptor = nix::fcntl::open(
        "/",
        nix::fcntl::OFlag::O_PATH | nix::fcntl::OFlag::O_CLOEXEC,
        nix::sys::stat::Mode::empty(),
    )?;
    let file = std::fs::File::from(descriptor);
    assert!(async_pipe(file).is_err());
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

#[tokio::test]
async fn cleanup_retry_does_not_wait_for_or_cancel_an_active_jailed_execution()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let host = JailLocalHost::with_backend(
        tinybox_jail::Jail::new(root.path(), "active retry fixture"),
        Arc::new(FixtureBackend),
        64,
    )?;
    let (completed, still_running) =
        super::super::observed_tests::retry_during_active_execution(Arc::new(host.clone())).await?;
    host.drain_checked().await?;
    assert!(completed, "cleanup retry must not join active executions");
    assert!(
        still_running,
        "cleanup retry must leave the active execution alone"
    );
    Ok(())
}

#[tokio::test]
async fn jail_permission_error_after_group_exit_is_successful_cleanup()
-> Result<(), Box<dyn std::error::Error>> {
    kill_jail_group(42, |_| Ok(()), |_| async { Ok(true) }).await?;
    kill_jail_group(
        42,
        |_| Err(nix::errno::Errno::ESRCH),
        |_| async { Ok(true) },
    )
    .await?;
    kill_jail_group(
        42,
        |_| Err(nix::errno::Errno::EPERM),
        |_| async { Ok(false) },
    )
    .await?;
    assert!(
        kill_jail_group(
            42,
            |_| Err(nix::errno::Errno::EPERM),
            |_| async { Ok(true) },
        )
        .await
        .is_err()
    );
    assert!(
        kill_jail_group(
            42,
            |_| Err(nix::errno::Errno::EPERM),
            |_| async { Err(failure("observe jail group", "probe failed".into())) },
        )
        .await
        .is_err()
    );
    Ok(())
}
