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
