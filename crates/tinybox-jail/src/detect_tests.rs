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
    assert_eq!(backend_name(), pick_backend().name());
}

#[cfg(target_os = "linux")]
#[test]
fn landlock_detection_matches_the_landlock_backend() {
    assert_eq!(
        landlock_available(),
        crate::linux::LandlockBackend::new().is_available()
    );
}

#[cfg(not(target_os = "linux"))]
#[test]
fn landlock_is_unavailable_off_linux() {
    assert!(!landlock_available());
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
fn linux_prefers_bubblewrap_then_landlock() {
    if crate::bwrap::BubblewrapBackend::new().is_available() {
        assert_eq!(pick_backend().name(), "bubblewrap");
    } else if crate::linux::LandlockBackend::new().is_available() {
        assert_eq!(pick_backend().name(), "landlock");
    }
}

#[cfg(target_os = "linux")]
#[test]
fn linux_candidates_rank_bubblewrap_before_landlock() {
    let names: Vec<_> = candidates().iter().map(|b| b.name()).collect();
    assert_eq!(names, ["bubblewrap", "landlock"]);
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

#[test]
fn owned_selection_skips_backends_without_owned_child_support() {
    struct OwnedCandidate(&'static str, bool);

    impl JailBackend for OwnedCandidate {
        fn name(&self) -> &'static str {
            self.0
        }
        fn is_available(&self) -> bool {
            true
        }
        fn is_owned_available(&self) -> bool {
            self.1
        }
        fn spawn(&self, _: &Jail, _: Command) -> std::io::Result<std::process::Child> {
            unreachable!("selection tests never spawn")
        }
    }

    let picked = pick_owned_from(vec![
        Arc::new(OwnedCandidate("legacy-only", false)),
        Arc::new(OwnedCandidate("owned", true)),
        Arc::new(OwnedCandidate("later-owned", true)),
    ]);
    assert_eq!(picked.name(), "owned");
    assert!(picked.is_owned_available());
}

#[test]
fn owned_selection_fails_closed_when_no_candidate_can_return_owned_child() {
    struct LegacyOnly;

    impl JailBackend for LegacyOnly {
        fn name(&self) -> &'static str {
            "legacy-only"
        }
        fn is_available(&self) -> bool {
            true
        }
        fn is_owned_available(&self) -> bool {
            false
        }
        fn spawn(&self, _: &Jail, _: Command) -> std::io::Result<std::process::Child> {
            unreachable!("selection tests never spawn")
        }
    }

    let picked = pick_owned_from(vec![Arc::new(LegacyOnly)]);
    assert_eq!(picked.name(), UNSUPPORTED_BACKEND_NAME);
    assert!(!picked.is_owned_available());
}
