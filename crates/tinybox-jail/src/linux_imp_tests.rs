//! Tests for unavailable kernels and enforcement status handling.

use super::imp::{check_enforcement, spawn_with_support};
use super::*;
use landlock::RulesetStatus;

#[test]
fn unsupported_kernel_never_runs_the_command() -> io::Result<()> {
    let root = tempfile::tempdir()?;
    let marker = root.path().join("ran");
    let mut cmd = Command::new("/bin/touch");
    cmd.arg(&marker);
    let result = spawn_with_support(&Jail::new(root.path(), "unsupported"), cmd, false);
    assert_eq!(
        result.err().map(|e| e.kind()),
        Some(io::ErrorKind::Unsupported)
    );
    assert!(!marker.exists());
    Ok(())
}

#[test]
fn only_fully_enforced_rulesets_are_accepted() -> io::Result<()> {
    assert_eq!(
        check_enforcement(&RulesetStatus::NotEnforced, "test")
            .err()
            .map(|e| e.kind()),
        Some(io::ErrorKind::Unsupported)
    );
    assert_eq!(
        check_enforcement(&RulesetStatus::PartiallyEnforced, "test")
            .err()
            .map(|e| e.kind()),
        Some(io::ErrorKind::Unsupported)
    );
    check_enforcement(&RulesetStatus::FullyEnforced, "test")?;
    assert_default_name::<LandlockBackend>("landlock");
    Ok(())
}

/// Check the default-construction contract through the backend trait.
fn assert_default_name<B: JailBackend + Default>(name: &str) {
    assert_eq!(B::default().name(), name);
}
