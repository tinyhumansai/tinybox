//! A rootless, kernel-isolated tinybox sandbox built on Linux namespaces.
//!
//! [`NamespaceSandbox`] gives a workload a private process table, mount tree,
//! and network namespace without a daemon, without root, and without any
//! privileged component of tinybox's own.
//!
//! ```no_run
//! use std::sync::Arc;
//! use tinybox_core::{BoxSpec, HostRef, MemoryStore, Placement, Sandbox, SandboxRef, WorkspaceSource};
//! use tinybox_host::LocalHost;
//! use tinybox_linux::NamespaceSandbox;
//!
//! # async fn run() -> tinybox_core::Result<()> {
//! let sandbox = NamespaceSandbox::new(Arc::new(LocalHost::new()), Arc::new(MemoryStore::new()));
//! assert!(sandbox.capabilities().is_suitable_for_untrusted_code());
//!
//! let spec = BoxSpec::new(
//!     Placement::new(HostRef::new("local")?, SandboxRef::new("namespace")?),
//!     WorkspaceSource::LocalDir("/srv/work".into()),
//! );
//! let info = sandbox.create(&spec).await?;
//! # let _ = info;
//! # Ok(())
//! # }
//! ```
//!
//! # No `unsafe`, and why that surprised the plan
//!
//! ADR 0003 reserved this crate as the one place `unsafe` would be allowed,
//! expecting raw `clone`, `pivot_root`, and seccomp calls. It is not needed:
//! namespace setup goes through `bwrap`, which on modern Ubuntu is the *only*
//! way an unprivileged process can create a user namespace at all, because
//! `kernel.apparmor_restrict_unprivileged_userns` blocks unconfined binaries
//! from doing it. ADR 0005 records the decision; the workspace keeps
//! `unsafe_code = "deny"` by default across the workspace. The single Windows
//! FFI exception is scoped to `tinybox-jail/src/windows.rs` and checked in CI.
//!
//! # What this backend does not do
//!
//! A box is a record and a bound directory, not a running container. Each
//! command is a fresh sandbox, so writes outside the workspace do not survive
//! between commands — which is why no snapshot or fork support is declared.

mod probe;
mod sandbox;

pub use probe::{NamespaceProbe, UsernsStatus};

pub use sandbox::{
    NAME, NamespaceSandbox, NativeJailCommand, WORKSPACE_MOUNT, native_jail_argv,
    native_jail_argv_with_programs, trusted_systemd_run_program,
};
