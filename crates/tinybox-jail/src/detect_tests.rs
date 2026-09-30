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
