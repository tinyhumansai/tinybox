//! Validation and environment behavior before process admission.
use super::*;
fn request(state: &Path) -> ShellExecRequest {
    ShellExecRequest {
        process: tinybox_bus::ResourceId("p".into()),
        resource: tinybox_bus::ResourceId("r".into()),
        shell: tinybox_bus::SelectShellRequest {
            command: "echo accepted".into(),
            preserve_pipeline_status: false,
            runtime_path: None,
            python_utf8: false,
        },
        cwd: None,
        extra_env: std::collections::BTreeMap::new(),
        state_dir: state.to_string_lossy().into_owned(),
        timeout_ms: 1000,
        stdin: None,
        jail: None,
        hide_window: false,
    }
}
#[test]
fn invalid_shell_state_budget_and_environment_are_refused_before_execution()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let state = tempfile::tempdir()?;
    let resolved = tinybox_core::ExecRequest::new(["unused"]);
    let original = request(state.path());
    for timeout in [0, 86_400_001] {
        let mut invalid = original.clone();
        invalid.timeout_ms = timeout;
        assert!(ShellContext::prepare(invalid, state.path(), &resolved).is_err());
    }
    for directory in ["relative", "absent", "nul\0"] {
        let mut invalid = original.clone();
        invalid.state_dir = directory.into();
        assert!(ShellContext::prepare(invalid, state.path(), &resolved).is_err());
    }
    let file = state.path().join("file");
    std::fs::write(&file, "data")?;
    let mut invalid = original.clone();
    invalid.state_dir = file.to_string_lossy().into_owned();
    assert!(ShellContext::prepare(invalid, state.path(), &resolved).is_err());
    let mut invalid = original.clone();
    invalid.shell.command = "nul\0".into();
    assert!(ShellContext::prepare(invalid, state.path(), &resolved).is_err());
    for (name, value) in [("", "value"), ("NAME=bad", "value"), ("NAME", "nul\0")] {
        let mut invalid = original.clone();
        invalid.extra_env.insert(name.into(), value.into());
        assert!(ShellContext::prepare(invalid, state.path(), &resolved).is_err());
    }
    Ok(())
}
#[test]
fn approved_environment_overrides_preserve_custom_temporary_directory_and_remove_startup_hooks()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let state = tempfile::tempdir()?;
    let resolved = tinybox_core::ExecRequest::new(["unused"]);
    let mut request = request(state.path());
    request
        .extra_env
        .insert("TMPDIR".into(), "approved-temporary-location".into());
    request
        .extra_env
        .insert("SHELLOPTS".into(), "errexit".into());
    let shell = ShellContext::prepare(request, state.path(), &resolved)?;
    assert_eq!(
        shell.environment.get("TMPDIR").map(String::as_str),
        Some("approved-temporary-location")
    );
    #[cfg(unix)]
    assert_eq!(shell.environment.get("SHELLOPTS"), None);
    assert!(!shell.pending());
    Ok(())
}

#[cfg(unix)]
struct Backend {
    full: bool,
}
#[cfg(unix)]
impl tinybox_jail::JailBackend for Backend {
    fn name(&self) -> &'static str {
        "native-shell-preflight-fixture"
    }
    fn is_available(&self) -> bool {
        true
    }
    fn isolation(&self) -> tinybox_core::IsolationLevel {
        tinybox_core::IsolationLevel::None
    }
    fn is_suitable_for_untrusted_code(&self) -> bool {
        true
    }
    fn is_suitable_for_untrusted_jail(&self, _: &tinybox_jail::Jail) -> bool {
        true
    }
    fn constraint_support(&self) -> tinybox_core::ConstraintSupport {
        use tinybox_core::{Constraint, ConstraintSupport, Enforcement};
        if self.full {
            ConstraintSupport::NONE
                .with(Constraint::Filesystem, Enforcement::Enforced)
                .with(Constraint::Network, Enforcement::Enforced)
                .with(Constraint::Subprocess, Enforcement::Enforced)
        } else {
            ConstraintSupport::NONE.with(Constraint::Filesystem, Enforcement::BestEffort)
        }
    }
    fn spawn(
        &self,
        jail: &tinybox_jail::Jail,
        mut command: std::process::Command,
    ) -> std::io::Result<std::process::Child> {
        assert!(jail.read_write.iter().any(|path| {
            path.components()
                .any(|component| component.as_os_str() == "sandbox-scratch")
        }));
        command.spawn()
    }
}
#[cfg(unix)]
#[tokio::test]
async fn native_shell_jail_adds_owned_scratch_and_refuses_unsupported_constraints()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let state = tempfile::tempdir()?;
    let mut resolved = tinybox_core::ExecRequest::new(["unused"]);
    resolved.cwd = Some(state.path().to_path_buf());
    let mut request = request(state.path());
    // The approved environment reaches the jailed shell.
    request.shell.command = r#"test "$TINYBOX_APPROVED" = visible"#.into();
    request
        .extra_env
        .insert("TINYBOX_APPROVED".into(), "visible".into());
    request.jail = Some(tinybox_bus::NativeJailConfig {
        read_only: vec![],
        read_write: vec![],
        allow_net: false,
        allow_subprocess: false,
        enforcement: tinybox_bus::JailEnforcement::Enforced,
        require_process_isolation: false,
        deny_read: Vec::new(),
        resources: None,
    });
    let shell = ShellContext::prepare_with_backend(
        request.clone(),
        state.path(),
        &resolved,
        Arc::new(Backend { full: true }),
    )?;
    assert_eq!(
        shell
            .run(
                &resolved,
                Arc::new(super::super::output::OutputJournal::default())
            )
            .await?
            .exit_code,
        0
    );
    assert!(!shell.pending());
    shell.drain().await?;
    let config = request.jail.as_mut().ok_or("missing jail fixture")?;
    config.enforcement = tinybox_bus::JailEnforcement::Declared;
    let shell = ShellContext::prepare_with_backend(
        request.clone(),
        state.path(),
        &resolved,
        Arc::new(Backend { full: true }),
    )?;
    shell.drain().await?;
    assert!(
        ShellContext::prepare_with_backend(
            request,
            state.path(),
            &resolved,
            Arc::new(Backend { full: false })
        )
        .is_err()
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn scratch_deletion_runs_outside_the_async_worker()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let state = tempfile::tempdir()?;
    let resolved = tinybox_core::ExecRequest::new(["unused"]);
    let shell = ShellContext::prepare(request(state.path()), state.path(), &resolved)?;
    let observed = Arc::new(std::sync::Mutex::new(None));
    let recorded = observed.clone();
    let worker = std::thread::current().id();
    shell
        .dispose_scratch_with(move |path| {
            *recorded
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) =
                Some(std::thread::current().id());
            std::fs::remove_dir_all(path)
        })
        .await?;
    assert_ne!(
        *observed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
        Some(worker),
        "recursive filesystem deletion must not run on the sole async worker"
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn scratch_preparation_runs_outside_the_async_worker()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let state = tempfile::tempdir()?;
    let root = state.path().to_path_buf();
    let request = request(&root);
    let resolved = tinybox_core::ExecRequest::new(["unused"]);
    let observed = Arc::new(std::sync::Mutex::new(None));
    let recorded = observed.clone();
    let worker = std::thread::current().id();
    let shell = ShellContext::prepare_owned_with(move || {
        *recorded
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(std::thread::current().id());
        ShellContext::prepare(request, &root, &resolved)
    })
    .await?;
    assert_ne!(
        *observed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
        Some(worker),
        "filesystem preparation must not run on the sole async worker"
    );
    shell.dispose_scratch().await?;
    Ok(())
}

#[test]
fn missing_state_and_blocked_scratch_paths_are_refused()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let state = tempfile::tempdir()?;
    let resolved = tinybox_core::ExecRequest::new(["unused"]);
    for root in [state.path().join("missing"), state.path().to_path_buf()] {
        std::fs::write(state.path().join("artifacts"), "blocks scratch creation")?;
        assert!(matches!(
            ShellContext::prepare(request(&root), &root, &resolved),
            Err(tinybus::Error::MethodFailed { name, .. }) if name == tinybox_bus::INVALID_SHELL_EXEC
        ));
    }
    Ok(())
}

#[test]
fn native_shell_preserves_resource_environment_and_request_overrides()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let state = tempfile::tempdir()?;
    let mut resolved = tinybox_core::ExecRequest::new(["unused"]);
    resolved
        .env
        .insert("RESOURCE_CONFIG".into(), "preserved".into());
    resolved.env.insert("TMPDIR".into(), "resource-temp".into());
    resolved.env.insert("OVERRIDE".into(), "resource".into());
    let mut request = request(state.path());
    request
        .extra_env
        .insert("OVERRIDE".into(), "request".into());
    let shell = ShellContext::prepare(request, state.path(), &resolved)?;
    assert_eq!(
        shell.environment.get("RESOURCE_CONFIG").map(String::as_str),
        Some("preserved")
    );
    assert_eq!(
        shell.environment.get("TMPDIR").map(String::as_str),
        Some("resource-temp")
    );
    assert_eq!(
        shell.environment.get("OVERRIDE").map(String::as_str),
        Some("request")
    );
    Ok(())
}

#[test]
fn python_utf8_defaults_apply_only_when_requested_and_yield_to_approved_overrides()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let state = tempfile::tempdir()?;
    let resolved = tinybox_core::ExecRequest::new(["unused"]);
    let plain = ShellContext::prepare(request(state.path()), state.path(), &resolved)?;
    assert_eq!(plain.environment.get("PYTHONIOENCODING"), None);
    let mut asked = request(state.path());
    asked.shell.python_utf8 = true;
    asked
        .extra_env
        .insert("PYTHONIOENCODING".into(), "latin-1".into());
    let shell = ShellContext::prepare(asked, state.path(), &resolved)?;
    assert!(shell.environment.contains_key("PYTHONUTF8"));
    assert_eq!(
        shell
            .environment
            .get("PYTHONIOENCODING")
            .map(String::as_str),
        Some("latin-1")
    );
    Ok(())
}

#[test]
fn window_flags_never_change_what_is_executed() {
    let mut hidden = std::process::Command::new("tool");
    hidden.arg("a");
    apply_window_flags(&mut hidden, true);
    assert_eq!(hidden.get_program(), "tool");
    assert_eq!(hidden.get_args().collect::<Vec<_>>(), ["a"]);
}

/// Reaches the `CREATE_NO_WINDOW` branch: a hidden console child still runs.
#[cfg(windows)]
#[test]
fn a_child_started_without_a_console_window_still_runs() {
    let mut command = std::process::Command::new("cmd");
    command.args(["/C", "exit 0"]);
    apply_window_flags(&mut command, true);
    assert!(command.status().expect("child starts").success());
}
