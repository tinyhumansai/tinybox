//! Platform auto-detection. Picks the strongest available backend.

use std::sync::Arc;

use super::jail::{Jail, JailBackend};
use std::process::{Child, Command};

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
pub fn pick_backend() -> Arc<dyn JailBackend> {
    #[cfg(target_os = "linux")]
    {
        let lb = super::linux::LandlockBackend::new();
        if lb.is_available() {
            log::info!("[cwd_jail] backend=landlock");
            return Arc::new(lb);
        }
    }
    #[cfg(target_os = "macos")]
    {
        let sb = super::macos::SeatbeltBackend::new();
        if sb.is_available() {
            log::info!("[cwd_jail] backend=seatbelt");
            return Arc::new(sb);
        }
    }
    #[cfg(target_os = "windows")]
    {
        let ac = super::windows::AppContainerBackend::new();
        if ac.is_available() {
            log::info!("[cwd_jail] backend=appcontainer");
            return Arc::new(ac);
        }
    }
    log::warn!("[cwd_jail] no OS sandbox available");
    Arc::new(UnsupportedBackend)
}
