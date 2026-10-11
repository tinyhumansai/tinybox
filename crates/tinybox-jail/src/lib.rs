//! Directory jail (`cwd_jail)`: jail an agent/tool into a single workspace.
//!
//! ## Why this exists
//!
//! `tinybox-linux` isolates a whole box with namespaces; this crate is a
//! different, lighter mechanism: it confines a single spawned `Command` to one
//! directory tree using whatever the host OS offers, with no daemon and no
//! container runtime.
//!
//! This crate is the user-facing facade. Callers describe *what* the
//! jail looks like ([`Jail`]) and the module picks the right OS backend:
//!
//! | OS      | Backend       | Mechanism                                  |
//! |---------|---------------|--------------------------------------------|
//! | Linux   | landlock      | Kernel 5.13+ LSM, applied on a spawn thread |
//! | macOS   | seatbelt      | `sandbox-exec -p '<profile>' …`            |
//! | Windows | (not compiled)| `AppContainer`, pending a `Child` bridge   |
//! | other   | unsupported   | Spawning is rejected                       |
//!
//! The Windows backend is not compiled yet (see `windows.rs`); on Windows the
//! default backend is `unsupported` and a host must opt into `NoopBackend`.
//!
//! ## Quick start
//!
//! ```ignore
//! use tinybox_jail::{spawn, Jail};
//! use std::process::Command;
//!
//! let mut jail = Jail::new("/Users/x/work/proj", "agent.delegate")
//!     .add_read_only("/usr/lib")
//!     .deny_subprocess();
//! jail.canonicalize_or_log();
//!
//! let mut cmd = Command::new("node");
//! cmd.arg("script.js");
//! let child = spawn(&jail, cmd)?;
//! ```
//!
//! ## What this does *not* do
//!
//! - It does not jail the current process. Backends spawn a child. The core
//!   itself is trusted; only the things it shells out to are caged.
//! - It does not decide *whether* a command may run. The host applies its own
//!   policy first; this crate decides *what filesystem* the command sees once
//!   approved.
//! - It does not encrypt files. ACLs / Landlock rules / Seatbelt profiles
//!   are the wall — anything inside `root` is fully visible to the child.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod detect;
pub mod jail;
pub mod noop;
pub mod registry;

// Platform backends. Linux (Landlock) is compiled on Linux only. The Seatbelt
// module is plain `std` (it shells out to `sandbox-exec`), so it compiles
// everywhere and its profile renderer is unit-tested on every host; it is only
// *selected* on macOS. The Windows AppContainer module (`windows.rs`) is
// deliberately not compiled: it needs `unsafe` FFI the workspace forbids and
// cannot yet return a waitable `std::process::Child`.
#[cfg(target_os = "linux")]
pub mod linux;
pub mod macos;

pub use jail::{Jail, JailBackend};
#[cfg(target_os = "linux")]
pub use linux::LandlockBackend;
pub use macos::SeatbeltBackend;
pub use noop::{NOOP_BACKEND_NAME, NoopBackend};
pub use registry::{JailRecord, JailRegistry};

use std::process::{Child, Command};
use std::sync::{Arc, OnceLock};

/// Cached default backend for the current platform.
static DEFAULT_BACKEND: OnceLock<Arc<dyn JailBackend>> = OnceLock::new();

/// Returns the process-wide default backend, lazily auto-detected.
pub fn default_backend() -> Arc<dyn JailBackend> {
    DEFAULT_BACKEND.get_or_init(detect::pick_backend).clone()
}

/// Spawn `cmd` inside the jail described by `jail`, using the default backend.
///
/// `jail.canonicalize()` is called once here so the backends never see
/// `..` or symlinks. If the root does not exist, the spawn fails with
/// `NotFound` (canonicalize bubbles it up) — callers should create the
/// workspace before encapsulating.
///
/// This legacy entry point does not require fully enforced constraints. Use
/// [`spawn_required`] for a hard preflight before spawning.
///
/// # Errors
///
/// Returns an error if the jail root cannot be canonicalized or the backend
/// rejects the command.
pub fn spawn(jail: &Jail, cmd: Command) -> std::io::Result<Child> {
    let mut jail = jail.clone();
    jail.canonicalize()?;
    default_backend().spawn(&jail, cmd)
}

/// Same as [`spawn`] but with a caller-supplied backend. Useful in
/// tests and for callers that want to opt into a weaker backend
/// explicitly (e.g. forcing [`NoopBackend`] during local dev).
///
/// This legacy entry point does not run [`JailBackend::require`]. Use
/// [`spawn_required_with`] when partial or absent enforcement must be refused.
///
/// # Errors
///
/// Returns an error if the jail root cannot be canonicalized or the backend
/// rejects the command.
pub fn spawn_with(backend: &dyn JailBackend, jail: &Jail, cmd: Command) -> std::io::Result<Child> {
    let mut jail = jail.clone();
    jail.canonicalize()?;
    backend.spawn(&jail, cmd)
}

/// Spawn captured native work using an explicitly chosen provider.
/// The caller retains the returned child and owns its pipes and cleanup.
/// # Errors
/// Returns a canonicalization, confinement, or native startup error.
pub fn spawn_captured_with(
    backend: &dyn JailBackend,
    jail: &Jail,
    cmd: Command,
) -> std::io::Result<Child> {
    let mut jail = jail.clone();
    jail.canonicalize()?;
    backend.spawn_captured(&jail, cmd)
}

/// Spawn only after all jail constraints pass a hard preflight.
///
/// This strict entry point rejects the explicitly trusted no-op backend and
/// Seatbelt's partial filesystem policy. Landlock can satisfy filesystem-only
/// requests, but offers no process isolation and is unsuitable for arbitrary
/// untrusted code. Availability and actual policy application are also checked
/// by the backend when spawning.
///
/// # Errors
/// Returns `Unsupported` before spawning for partial or unsupported constraints,
/// or a filesystem/backend error while canonicalizing or applying the policy.
pub fn spawn_required_with(
    backend: &dyn JailBackend,
    jail: &Jail,
    cmd: Command,
) -> std::io::Result<Child> {
    backend
        .require(jail)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::Unsupported, error))?;
    spawn_with(backend, jail, cmd)
}

/// Spawn using the detected backend after a hard preflight.
///
/// # Errors
/// Returns the same preflight and setup errors as [`spawn_required_with`].
pub fn spawn_required(jail: &Jail, cmd: Command) -> std::io::Result<Child> {
    spawn_required_with(default_backend().as_ref(), jail, cmd)
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
