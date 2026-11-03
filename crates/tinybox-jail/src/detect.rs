//! Platform auto-detection. Picks the strongest available backend.

use std::process::{Child, Command};
use std::sync::Arc;

use super::jail::{Jail, JailBackend};

/// Name reported by the backend returned when no OS sandbox is usable.
pub const UNSUPPORTED_BACKEND_NAME: &str = "unsupported";

#[derive(Debug)]
struct UnsupportedBackend;

impl JailBackend for UnsupportedBackend {
    fn name(&self) -> &'static str {
        UNSUPPORTED_BACKEND_NAME
    }

    fn is_available(&self) -> bool {
        false
    }

    fn spawn(&self, _: &Jail, _: Command) -> std::io::Result<Child> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "no supported jail backend is available",
        ))
    }
}

/// The OS backends this build knows about, strongest first.
///
/// Windows `AppContainer` is intentionally absent: it cannot hand back a
/// waitable `std::process::Child` yet (see `windows.rs`).
#[cfg(target_os = "linux")]
fn candidates() -> Vec<Arc<dyn JailBackend>> {
    vec![
        Arc::new(crate::bwrap::BubblewrapBackend::new()),
        Arc::new(crate::linux::LandlockBackend::new()),
    ]
}

/// The OS backends this build knows about, strongest first.
#[cfg(target_os = "macos")]
fn candidates() -> Vec<Arc<dyn JailBackend>> {
    vec![Arc::new(crate::macos::SeatbeltBackend::new())]
}

/// The OS backends this build knows about, strongest first. None here.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn candidates() -> Vec<Arc<dyn JailBackend>> {
    Vec::new()
}

#[cfg(target_os = "windows")]
fn owned_candidates() -> Vec<Arc<dyn JailBackend>> {
    vec![Arc::new(crate::windows::AppContainerBackend::new())]
}

#[cfg(not(target_os = "windows"))]
fn owned_candidates() -> Vec<Arc<dyn JailBackend>> {
    candidates()
}

/// Picks the first available OS backend (bubblewrap then Landlock on Linux,
/// Seatbelt on macOS). When none works it logs a warning and returns an unsupported
/// backend whose `is_available` is `false` and whose `spawn` fails with
/// `ErrorKind::Unsupported`. It never silently returns an unconfined backend:
/// a caller that wants to run unconfined must choose `NoopBackend` itself.
#[must_use]
pub fn pick_backend() -> Arc<dyn JailBackend> {
    pick_from(candidates())
}

/// Picks the strongest available backend that can return an [`super::jail::OwnedChild`].
#[must_use]
pub fn pick_owned_backend() -> Arc<dyn JailBackend> {
    pick_owned_from(owned_candidates())
}

/// Select the first backend that can return an owned child.
fn pick_owned_from(backends: Vec<Arc<dyn JailBackend>>) -> Arc<dyn JailBackend> {
    for backend in backends {
        if backend.is_owned_available() {
            log::debug!(
                "[cwd_jail] selected owned-process sandbox {}",
                backend.name()
            );
            return backend;
        }
        log::debug!(
            "[cwd_jail] owned-process sandbox {} is unavailable",
            backend.name()
        );
    }
    log::warn!("[cwd_jail] no owned-process sandbox available; jailed spawns are unsupported");
    Arc::new(UnsupportedBackend)
}

/// Returns the stable name of the backend selected by platform detection.
#[must_use]
pub fn backend_name() -> &'static str {
    pick_backend().name()
}

/// Reports whether this build and running Linux kernel support Landlock.
///
/// This is always false off Linux and when the `landlock` feature is disabled.
#[must_use]
pub fn landlock_available() -> bool {
    #[cfg(target_os = "linux")]
    {
        crate::linux::LandlockBackend::new().is_available()
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// Select an available backend from the ordered platform candidates.
fn pick_from(backends: Vec<Arc<dyn JailBackend>>) -> Arc<dyn JailBackend> {
    for backend in backends {
        if backend.is_available() {
            log::debug!("[cwd_jail] selected OS sandbox backend {}", backend.name());
            return backend;
        }
        log::debug!("[cwd_jail] backend {} is not available", backend.name());
    }
    log::warn!("[cwd_jail] no OS sandbox available; jailed spawns are unsupported");
    Arc::new(UnsupportedBackend)
}

#[cfg(test)]
#[path = "detect_tests.rs"]
mod tests;
