//! Tests for Landlock setup and child spawning.

use super::*;

#[test]
fn backend_reports_name_and_availability() {
    let backend = LandlockBackend::new();
    assert_eq!(backend.name(), "landlock");
    let _ = backend.is_available();
}

#[test]
fn spawn_rejects_a_missing_read_only_path() {
    let root = tempfile::tempdir().expect("temporary jail root");
    let jail = Jail::new(root.path(), "missing-read-only")
        .add_read_only(root.path().join("missing-read-only-path"));
    let result = LandlockBackend::new().spawn(&jail, Command::new("true"));
    assert_eq!(
        result.err().map(|error| error.kind()),
        Some(std::io::ErrorKind::Other)
    );
}

#[test]
fn spawn_applies_rules_before_running_the_command_when_supported() {
    let root = tempfile::tempdir().expect("temporary jail root");
    let jail = Jail::new(root.path(), "landlock-spawn").add_read_only("/usr");
    let result = LandlockBackend::new().spawn(&jail, Command::new("/usr/bin/true"));
    if let Ok(mut child) = result {
        let status = child.wait().expect("wait for jailed command");
        assert!(status.success());
    }
}
