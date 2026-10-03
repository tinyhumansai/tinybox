//! Tests for backend selection and the unavailable-backend result.

use super::*;

#[test]
fn unavailable_backend_rejects_spawning() {
    let backend = UnsupportedBackend;
    assert_eq!(backend.name(), UNSUPPORTED_BACKEND_NAME);
    assert!(!backend.is_available());
    let error = backend
        .spawn(&Jail::new(".", "unsupported"), Command::new("true"))
        .err()
        .map(|error| error.kind());
    assert_eq!(error, Some(std::io::ErrorKind::Unsupported));
}

#[test]
fn backend_detection_returns_a_backend() {
    assert_ne!(pick_backend().name().len(), 0);
}

#[test]
fn detection_prefers_the_platform_backend_when_it_works() {
    let picked = pick_backend();
    let expected = candidates()
        .into_iter()
        .find(|backend| backend.is_available());
    if let Some(backend) = expected {
        assert_eq!(picked.name(), backend.name());
        assert!(picked.is_available());
    } else {
        assert_eq!(picked.name(), UNSUPPORTED_BACKEND_NAME);
        assert!(!picked.is_available());
    }
}

#[cfg(all(target_os = "linux", feature = "landlock"))]
#[test]
fn linux_with_landlock_selects_landlock_on_a_supporting_kernel() {
    if crate::linux::LandlockBackend::new().is_available() {
        assert_eq!(pick_backend().name(), "landlock");
    }
}

#[test]
fn windows_appcontainer_is_never_a_candidate() {
    assert!(
        candidates()
            .iter()
            .all(|backend| backend.name() != "appcontainer")
    );
}

#[test]
fn unavailable_candidates_are_skipped_and_empty_candidates_fail_closed() {
    for candidates in [
        vec![],
        vec![Arc::new(UnsupportedBackend) as Arc<dyn JailBackend>],
    ] {
        let picked = pick_from(candidates);
        assert_eq!(picked.name(), UNSUPPORTED_BACKEND_NAME);
        assert!(!picked.is_available());
    }
}

#[test]
fn selection_uses_the_first_available_candidate() {
    let picked = pick_from(vec![
        Arc::new(UnsupportedBackend),
        Arc::new(crate::noop::NoopBackend),
    ]);
    assert_eq!(picked.name(), crate::noop::NOOP_BACKEND_NAME);
}
