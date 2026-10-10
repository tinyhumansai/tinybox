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
fn spawn_uses_default_backend() {
    let dir = std::env::temp_dir();
    // Landlock denies everything it is not told about; give it the system
    // directories so `true` can run. Other backends ignore the extra grants.
    let jail = ["/usr", "/bin", "/lib", "/lib64"]
        .into_iter()
        .filter(|path| std::path::Path::new(path).exists())
        .fold(Jail::new(&dir, "default-spawn"), Jail::add_read_only);
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
        let mut child = result.expect("spawn through available backend");
        let _ = child.wait().expect("wait");
    } else {
        assert_eq!(
            result.err().map(|error| error.kind()),
            Some(std::io::ErrorKind::Unsupported)
        );
    }
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

#[cfg(target_os = "linux")]
#[test]
fn strict_landlock_filesystem_only_spawn_still_works() -> std::io::Result<()> {
    use crate::JailBackend;
    let backend = crate::LandlockBackend::new();
    if !backend.is_available() {
        return Ok(());
    }
    let root = tempfile::tempdir()?;
    let jail = crate::Jail::new(root.path(), "strict-fs");
    assert_eq!(
        backend.plan_check(&jail).constraints,
        [(
            tinybox_core::Constraint::Filesystem,
            tinybox_core::Enforcement::Enforced
        )]
    );
    let mut child =
        crate::spawn_required_with(&backend, &jail, std::process::Command::new("/usr/bin/true"))?;
    assert!(child.wait()?.success());
    Ok(())
}

#[test]
fn seatbelt_launcher_presence_never_claims_verified_enforcement() {
    use crate::JailBackend;
    use tinybox_core::{Constraint, Enforcement};
    let backend = crate::SeatbeltBackend::new();
    let support = backend.constraint_support();
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
    let jail = crate::Jail::new(root.path(), "strict-default");
    let result = crate::spawn_required(&jail, std::process::Command::new("/usr/bin/true"));
    if crate::default_backend()
        .constraint_support()
        .enforcement(Constraint::Filesystem)
        == Enforcement::Enforced
    {
        assert!(result?.wait()?.success());
    } else {
        assert_eq!(
            result.err().map(|error| error.kind()),
            Some(std::io::ErrorKind::Unsupported)
        );
    }
    Ok(())
}
