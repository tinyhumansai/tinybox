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
    assert!(!b.name().is_empty());
}

#[test]
fn default_backend_is_cached() {
    // OnceLock guarantees the same Arc on every call.
    let a = default_backend();
    let b = default_backend();
    assert!(Arc::ptr_eq(&a, &b));
}

#[test]
#[cfg(not(feature = "landlock"))]
fn spawn_uses_default_backend() {
    let dir = std::env::temp_dir();
    let jail = Jail::new(&dir, "default-spawn")
        .add_read_only("/usr")
        .add_read_only("/bin")
        .add_read_only("/lib")
        .add_read_only("/lib64");
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
        match result {
            Ok(mut child) => {
                let _ = child.wait();
            }
            Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied),
        }
    } else {
        assert_eq!(
            result.err().map(|error| error.kind()),
            Some(std::io::ErrorKind::Unsupported)
        );
    }
}

#[test]
fn spawn_uses_default_backend_for_an_existing_root() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let result = super::spawn(
        &Jail::new(dir.path(), "default-spawn"),
        Command::new("true"),
    );
    match result {
        Ok(mut child) => {
            let _ = child.wait();
        }
        Err(error) => assert!(matches!(
            error.kind(),
            std::io::ErrorKind::Unsupported | std::io::ErrorKind::PermissionDenied
        )),
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
