//! Tests for the public jail spawning facade.

use super::*;

#[test]
fn noop_backend_spawns_unrestricted() {
    let dir = std::env::temp_dir();
    let jail = Jail::new(&dir, "test.noop");
    let mut child = spawn_with(&NoopBackend, &jail, {
        let mut c = Command::new(if cfg!(windows) { "cmd" } else { "true" });
        if cfg!(windows) {
            c.args(["/C", "exit"]);
        }
        c
    })
    .expect("noop spawn");
    let status = child.wait().expect("wait");
    assert!(status.success() || cfg!(windows));
}

#[test]
fn jail_builder_chains() {
    let j = Jail::new("/tmp", "x")
        .add_read_only("/usr/lib")
        .deny_net()
        .deny_subprocess();
    assert_eq!(j.read_only.len(), 1);
    assert!(!j.allow_net);
    assert!(!j.allow_subprocess);
}

#[test]
fn missing_root_errors() {
    let jail = Jail::new("/this/does/not/exist/ever", "x");
    let err = spawn_with(&NoopBackend, &jail, Command::new("true")).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
}

#[test]
fn facade_refuses_resource_limits_before_spawning() -> std::io::Result<()> {
    let root = tempfile::tempdir()?;
    let marker = root.path().join("executed");
    let mut jail = Jail::new(root.path(), "resources");
    jail.resources = Some(tinybox_core::Resources::DEFAULT);
    let mut command = if cfg!(windows) {
        let mut command = Command::new("cmd");
        command.args(["/C", "echo executed > executed"]);
        command
    } else {
        let mut command = Command::new("sh");
        command.args(["-c", "printf executed > executed"]);
        command
    };
    command.current_dir(root.path());
    let error = spawn_with(&NoopBackend, &jail, command).err();
    assert_eq!(
        error.map(|error| error.kind()),
        Some(std::io::ErrorKind::Unsupported)
    );
    assert!(!marker.exists());
    Ok(())
}

#[test]
fn facade_refuses_each_zero_resource_limit_even_when_backend_claims_enforcement()
-> std::io::Result<()> {
    use tinybox_core::{Constraint, ConstraintSupport, Enforcement, Error};

    struct FullyEnforcedBackend;

    impl JailBackend for FullyEnforcedBackend {
        fn name(&self) -> &'static str {
            "fully-enforced-test"
        }

        fn is_available(&self) -> bool {
            true
        }

        fn constraint_support(&self) -> ConstraintSupport {
            [
                Constraint::Filesystem,
                Constraint::Cpu,
                Constraint::Memory,
                Constraint::Pids,
                Constraint::Disk,
            ]
            .into_iter()
            .fold(ConstraintSupport::NONE, |support, constraint| {
                support.with(constraint, Enforcement::Enforced)
            })
        }

        fn spawn(&self, _jail: &Jail, mut cmd: Command) -> std::io::Result<std::process::Child> {
            cmd.spawn()
        }
    }

    let root = tempfile::tempdir()?;
    let marker = root.path().join("executed");
    let cases = [
        (
            "cpu_millis",
            tinybox_core::Resources {
                cpu_millis: 0,
                ..tinybox_core::Resources::DEFAULT
            },
        ),
        (
            "memory_bytes",
            tinybox_core::Resources {
                memory_bytes: 0,
                ..tinybox_core::Resources::DEFAULT
            },
        ),
        (
            "pids_max",
            tinybox_core::Resources {
                pids_max: 0,
                ..tinybox_core::Resources::DEFAULT
            },
        ),
        (
            "disk_bytes",
            tinybox_core::Resources {
                disk_bytes: 0,
                ..tinybox_core::Resources::DEFAULT
            },
        ),
    ];

    for (limit, resources) in cases {
        let jail = Jail {
            resources: Some(resources),
            ..Jail::new(root.path(), "invalid-resources")
        };
        let mut command = if cfg!(windows) {
            let mut command = Command::new("cmd");
            command.args(["/C", "echo executed > executed"]);
            command
        } else {
            let mut command = Command::new("sh");
            command.args(["-c", "printf executed > executed"]);
            command
        };
        command.current_dir(root.path());

        let error = spawn_with(&FullyEnforcedBackend, &jail, command).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(matches!(
            error.get_ref().and_then(|source| source.downcast_ref::<Error>()),
            Some(Error::ZeroResourceLimit { limit: invalid_limit }) if *invalid_limit == limit
        ));
        assert!(!marker.exists());
    }

    Ok(())
}

#[test]
fn facade_refuses_denials_nested_under_backend_implicit_grants() -> std::io::Result<()> {
    struct BaselineBackend {
        baseline: std::path::PathBuf,
    }

    impl JailBackend for BaselineBackend {
        fn implicit_grants(&self) -> Vec<std::path::PathBuf> {
            vec![self.baseline.clone()]
        }

        fn name(&self) -> &'static str {
            "baseline-test"
        }

        fn is_available(&self) -> bool {
            true
        }

        fn spawn(&self, _jail: &Jail, mut cmd: Command) -> std::io::Result<std::process::Child> {
            cmd.spawn()
        }
    }

    let root = tempfile::tempdir()?;
    let baseline_root = tempfile::tempdir()?;
    let baseline = baseline_root.path().join("implicit-baseline");
    std::fs::create_dir(&baseline)?;
    let marker = root.path().join("executed");
    let mut jail = Jail::new(root.path(), "baseline-denial");
    jail.deny_read.push(baseline.join("future-secret"));
    let mut command = if cfg!(windows) {
        let mut command = Command::new("cmd");
        command.args(["/C", "echo executed > executed"]);
        command
    } else {
        let mut command = Command::new("sh");
        command.args(["-c", "printf executed > executed"]);
        command
    };
    command.current_dir(root.path());

    let error = spawn_with(&BaselineBackend { baseline }, &jail, command).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    assert!(
        !marker.exists(),
        "backend must not spawn after denial conflict"
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn facade_spawns_without_denials_when_optional_implicit_grant_is_dangling() -> std::io::Result<()> {
    struct BaselineBackend {
        baseline: std::path::PathBuf,
        spawned: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    impl JailBackend for BaselineBackend {
        fn implicit_grants(&self) -> Vec<std::path::PathBuf> {
            vec![self.baseline.clone()]
        }

        fn name(&self) -> &'static str {
            "dangling-baseline-test"
        }

        fn is_available(&self) -> bool {
            true
        }

        fn spawn(&self, _jail: &Jail, mut cmd: Command) -> std::io::Result<std::process::Child> {
            self.spawned
                .store(true, std::sync::atomic::Ordering::SeqCst);
            cmd.spawn()
        }
    }

    let root = tempfile::tempdir()?;
    let baseline_root = tempfile::tempdir()?;
    let baseline = baseline_root.path().join("optional-baseline");
    std::os::unix::fs::symlink(baseline_root.path().join("missing-target"), &baseline)?;
    let spawned = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let backend = BaselineBackend {
        baseline,
        spawned: spawned.clone(),
    };
    let mut child = spawn_with(
        &backend,
        &Jail::new(root.path(), "optional-baseline"),
        Command::new("true"),
    )?;
    assert!(spawned.load(std::sync::atomic::Ordering::SeqCst));
    assert!(child.wait()?.success());
    Ok(())
}

#[cfg(unix)]
#[test]
fn facade_refuses_denials_when_implicit_grant_is_dangling() -> std::io::Result<()> {
    struct BaselineBackend {
        baseline: std::path::PathBuf,
        spawned: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    impl JailBackend for BaselineBackend {
        fn implicit_grants(&self) -> Vec<std::path::PathBuf> {
            vec![self.baseline.clone()]
        }

        fn name(&self) -> &'static str {
            "dangling-baseline-test"
        }

        fn is_available(&self) -> bool {
            true
        }

        fn spawn(&self, _jail: &Jail, mut cmd: Command) -> std::io::Result<std::process::Child> {
            self.spawned
                .store(true, std::sync::atomic::Ordering::SeqCst);
            cmd.spawn()
        }
    }

    let root = tempfile::tempdir()?;
    let baseline_root = tempfile::tempdir()?;
    let denial_root = tempfile::tempdir()?;
    let baseline = baseline_root.path().join("optional-baseline");
    std::os::unix::fs::symlink(baseline_root.path().join("missing-target"), &baseline)?;
    let spawned = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let backend = BaselineBackend {
        baseline,
        spawned: spawned.clone(),
    };
    let mut jail = Jail::new(root.path(), "denial-with-dangling-baseline");
    jail.deny_read
        .push(denial_root.path().join("future-denial"));

    let error = spawn_with(&backend, &jail, Command::new("true")).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
    assert!(!spawned.load(std::sync::atomic::Ordering::SeqCst));
    Ok(())
}

#[test]
fn default_backend_returns_something() {
    let b = default_backend();
    assert_ne!(b.name().len(), 0);
}

#[test]
fn default_backend_is_cached() {
    // OnceLock guarantees the same Arc on every call.
    let a = default_backend();
    let b = default_backend();
    assert!(Arc::ptr_eq(&a, &b));
}

#[test]
fn spawn_uses_default_backend() -> std::io::Result<()> {
    // A scratch directory, not `/tmp` itself: the bubblewrap backend refuses a
    // grant that would replace its private `/tmp`.
    let dir = tempfile::tempdir()?;
    // Landlock denies everything it is not told about; give it the system
    // directories so `true` can run. Other backends ignore the extra grants.
    let jail = ["/usr", "/bin", "/lib", "/lib64"]
        .into_iter()
        .filter(|path| std::path::Path::new(path).exists())
        .fold(Jail::new(dir.path(), "default-spawn"), Jail::add_read_only);
    let cmd = if cfg!(windows) {
        let mut c = Command::new("cmd");
        c.args(["/C", "exit"]);
        c
    } else {
        Command::new("true")
    };
    // Must succeed via whichever platform backend is detected (or
    // noop). The point of the test is that we go through the public
    // `spawn` entry rather than `spawn_with`.
    let result = spawn(&jail, cmd);
    if default_backend().is_available() {
        assert!(result?.wait()?.success());
    } else {
        assert_eq!(
            result.err().map(|error| error.kind()),
            Some(std::io::ErrorKind::Unsupported)
        );
    }
    Ok(())
}

#[test]
fn spawn_uses_default_backend_for_an_existing_root() -> std::io::Result<()> {
    let dir = tempfile::tempdir()?;
    let result = super::spawn(
        &Jail::new(dir.path(), "default-spawn"),
        Command::new("true"),
    );
    if default_backend().is_available() {
        assert!(result?.wait()?.success());
    } else {
        assert_eq!(
            result.err().map(|error| error.kind()),
            Some(std::io::ErrorKind::Unsupported)
        );
    }
    Ok(())
}

#[test]
fn canonicalize_or_log_does_not_panic_on_missing() {
    // The lossy helper is supposed to log + continue rather than
    // propagate. Verify it doesn't panic for the missing-root case.
    let mut jail = Jail::new("/no/such/place", "lossy");
    jail.canonicalize_or_log();
    // root stays as-is on failure.
    assert_eq!(jail.root, std::path::PathBuf::from("/no/such/place"));
}

#[test]
fn noop_backend_metadata() {
    assert_eq!(NoopBackend.name(), "noop");
    assert!(NoopBackend.is_available());
}

#[test]
fn strict_noop_preflight_never_spawns_a_command() -> std::io::Result<()> {
    use crate::{JailBackend, spawn_required_with};
    use tinybox_core::{Constraint, ConstraintSupport, Enforcement, IsolationLevel};
    let root = tempfile::tempdir()?;
    let marker = root.path().join("executed");
    let mut cmd = if cfg!(windows) {
        let mut command = std::process::Command::new("cmd");
        command.args(["/C", "echo executed > executed"]);
        command
    } else {
        let mut command = std::process::Command::new("sh");
        command.args(["-c", "printf executed > executed"]);
        command
    };
    cmd.current_dir(root.path());
    let backend = crate::NoopBackend;
    assert_eq!(backend.isolation(), IsolationLevel::None);
    assert_eq!(backend.constraint_support(), ConstraintSupport::NONE);
    assert!(!backend.is_suitable_for_untrusted_code());
    for jail in [
        crate::Jail::new(root.path(), "strict"),
        crate::Jail::new(root.path(), "strict")
            .deny_net()
            .deny_subprocess(),
    ] {
        let error = backend.require(&jail).err();
        assert!(matches!(
            error,
            Some(tinybox_core::Error::ConstraintNotEnforced {
                constraint: Constraint::Filesystem,
                enforcement: Enforcement::Unsupported,
                ..
            })
        ));
    }
    let result = spawn_required_with(&backend, &crate::Jail::new(root.path(), "strict"), cmd);
    assert_eq!(
        result.err().map(|e| e.kind()),
        Some(std::io::ErrorKind::Unsupported)
    );
    assert!(!marker.exists());
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn landlock_refuses_network_and_subprocess_denials_before_spawning() -> std::io::Result<()> {
    use crate::JailBackend;
    let backend = crate::LandlockBackend::new();
    let root = tempfile::tempdir()?;
    assert!(!backend.is_suitable_for_untrusted_code());
    for jail in [
        crate::Jail::new(root.path(), "net").deny_net(),
        crate::Jail::new(root.path(), "child").deny_subprocess(),
    ] {
        let result = backend.spawn(
            &jail,
            std::process::Command::new("definitely-not-a-command"),
        );
        assert_eq!(
            result.err().map(|e| e.kind()),
            Some(std::io::ErrorKind::Unsupported)
        );
    }
    Ok(())
}

/// Locate `true` only in the documented Landlock baseline, never in raw PATH.
fn permitted_true() -> std::io::Result<std::path::PathBuf> {
    ["/usr/bin/true", "/bin/true"]
        .into_iter()
        .map(std::path::PathBuf::from)
        .find(|path| path.is_file())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "neither baseline executable /usr/bin/true nor /bin/true exists",
            )
        })
}

#[cfg(target_os = "linux")]
#[test]
fn strict_landlock_filesystem_only_spawn_still_works() -> std::io::Result<()> {
    use crate::JailBackend;
    let backend = crate::LandlockBackend::new();
    if !backend.is_available() {
        return Ok(());
    }
    let root = tempfile::tempdir()?;
    let executable = permitted_true()?;
    let jail = crate::Jail::new(root.path(), "strict-fs").add_read_only(&executable);
    assert_eq!(
        backend.plan_check(&jail).constraints,
        [(
            tinybox_core::Constraint::Filesystem,
            tinybox_core::Enforcement::Enforced
        )]
    );
    let mut child =
        crate::spawn_required_with(&backend, &jail, std::process::Command::new(&executable))?;
    assert!(child.wait()?.success());
    Ok(())
}

#[test]
fn seatbelt_launcher_presence_never_claims_verified_enforcement() {
    use crate::JailBackend;
    use tinybox_core::{Constraint, Enforcement};
    let backend = crate::SeatbeltBackend::new();
    let support = backend.constraint_support();
    assert_eq!(backend.isolation(), tinybox_core::IsolationLevel::None);
    assert!(!backend.is_suitable_for_untrusted_code());
    assert_eq!(
        support.enforcement(Constraint::Filesystem),
        if backend.is_available() {
            Enforcement::BestEffort
        } else {
            Enforcement::Unsupported
        }
    );
    for constraint in [Constraint::Network, Constraint::Subprocess] {
        assert_eq!(
            support.enforcement(constraint),
            if backend.is_available() {
                Enforcement::BestEffort
            } else {
                Enforcement::Unsupported
            }
        );
    }
}

#[test]
fn strict_default_spawn_obeys_the_detected_filesystem_declaration() -> std::io::Result<()> {
    use tinybox_core::{Constraint, Enforcement};
    let root = tempfile::tempdir()?;
    let mut jail = crate::Jail::new(root.path(), "strict-default");
    let enforced = crate::default_backend()
        .constraint_support()
        .enforcement(Constraint::Filesystem)
        == Enforcement::Enforced;
    let command = if enforced {
        let executable = permitted_true()?;
        jail = jail.add_read_only(&executable);
        std::process::Command::new(executable)
    } else {
        std::process::Command::new("definitely-not-a-command")
    };
    let result = crate::spawn_required(&jail, command);
    if enforced {
        assert!(result?.wait()?.success());
    } else {
        assert_eq!(
            result.err().map(|error| error.kind()),
            Some(std::io::ErrorKind::Unsupported)
        );
    }
    Ok(())
}
