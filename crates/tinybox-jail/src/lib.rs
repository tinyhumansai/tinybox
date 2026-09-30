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
//! | Linux   | landlock      | Kernel 5.13+ LSM, applied in `pre_exec`    |
//! | macOS   | seatbelt      | `sandbox-exec -p '<profile>' …`            |
//! | Windows | appcontainer  | `CreateAppContainerProfile` + `STARTUPINFOEX` |
//! | other   | unsupported   | Spawning is rejected                       |
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

// Platform backends are intentionally not compiled until they can preserve
// the workspace unsafe-code policy and enforce the public jail contract.

pub use jail::{Jail, JailBackend};
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
/// # Errors
///
/// Returns an error if the jail root cannot be canonicalized or the backend
/// rejects the command.
pub fn spawn_with(backend: &dyn JailBackend, jail: &Jail, cmd: Command) -> std::io::Result<Child> {
    let mut jail = jail.clone();
    jail.canonicalize()?;
    backend.spawn(&jail, cmd)
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
