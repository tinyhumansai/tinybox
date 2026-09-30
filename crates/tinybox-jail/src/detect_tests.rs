//! Tests for platform backend selection and the unsupported fallback.

use super::*;

#[test]
fn unsupported_backend_reports_and_rejects_spawns() {
    let backend = UnsupportedBackend;
    assert_eq!(backend.name(), "unsupported");
    assert!(!backend.is_available());
    let error = backend
        .spawn(&Jail::new("/", "unsupported"), Command::new("true"))
        .err()
        .expect("unsupported backend must reject a spawn");
    assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
}

#[test]
fn backend_selection_returns_a_named_backend() {
    assert!(!pick_backend().name().is_empty());
}
