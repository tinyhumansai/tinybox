//! Platform auto-detection. Picks the strongest available backend.

use std::process::{Child, Command};
use std::sync::Arc;

use super::jail::{Jail, JailBackend};

#[derive(Debug)]
struct UnsupportedBackend;

impl JailBackend for UnsupportedBackend {
    fn name(&self) -> &'static str {
        "unsupported"
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

/// Picks the strongest available backend, returning an unsupported backend
/// when no OS sandbox works.
#[must_use]
pub fn pick_backend() -> Arc<dyn JailBackend> {
    log::warn!("[cwd_jail] no OS sandbox available");
    Arc::new(UnsupportedBackend)
}

#[cfg(test)]
#[path = "detect_tests.rs"]
mod tests;
