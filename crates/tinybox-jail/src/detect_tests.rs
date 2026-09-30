//! Tests for platform backend selection and the unsupported fallback.

use super::*;

#[test]
fn unsupported_backend_reports_and_rejects_spawns() {
    let backend = UnsupportedBackend;
    assert_eq!(backend.name(), "unsupported");
    assert!(!backend.is_available());
    let error = backend
        .spawn(&Jail::new("/", "unsupported"), Command::new("true"))
        .expect_err("unsupported backend must reject a spawn");
    assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
}

#[test]
fn backend_selection_returns_a_named_backend() {
    assert!(!pick_backend().name().is_empty());
}

#[test]
fn backend_selection_falls_back_when_no_backend_is_available() {
    let backend = pick_backend_with(|_| false);
    assert_eq!(backend.name(), "unsupported");
    assert!(!backend.is_available());
}

#[test]
fn availability_lookup_checks_only_the_named_backend() {
    assert!(!is_available("unknown"));
    #[cfg(target_os = "linux")]
    assert_eq!(
        is_available("landlock"),
        super::super::linux::LandlockBackend::new().is_available()
    );
}

#[test]
fn backend_selection_uses_an_available_platform_backend() {
    let backend = pick_backend_with(|_| true);
    #[cfg(target_os = "linux")]
    assert_eq!(backend.name(), "landlock");
    #[cfg(target_os = "macos")]
    assert_eq!(backend.name(), "seatbelt");
    #[cfg(target_os = "windows")]
    assert_eq!(backend.name(), "appcontainer");
}
