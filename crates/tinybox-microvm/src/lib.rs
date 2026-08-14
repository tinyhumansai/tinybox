//! A hardware-isolated tinybox sandbox backed by Firecracker microVMs.
//!
//! The strongest boundary tinybox offers. A container shares the host kernel,
//! so a kernel exploit escapes it; a microVM has its own kernel behind a
//! hypervisor and nothing to escape into. [`MicroVmSandbox`] is the only
//! backend that declares
//! [`IsolationLevel::Hardware`](tinybox_core::IsolationLevel::Hardware).
//!
//! ```no_run
//! use std::sync::Arc;
//! use tinybox_core::{MemoryStore, Sandbox};
//! use tinybox_host::LocalHost;
//! use tinybox_microvm::{GuestImage, MicroVmSandbox};
//!
//! # fn run() {
//! let sandbox = MicroVmSandbox::new(
//!     Arc::new(LocalHost::new()),
//!     Arc::new(MemoryStore::new()),
//!     GuestImage::with_kernel("/var/lib/tinybox/vmlinux"),
//! );
//! assert!(sandbox.capabilities().is_suitable_for_untrusted_code());
//! # }
//! ```
//!
//! # A VM per command
//!
//! Each command boots a fresh microVM — about 800 ms measured on the machine
//! this was built on, from launch to output to clean shutdown. That is what
//! makes the model viable: a VM per command is absurd at container-era boot
//! times and unremarkable at Firecracker's.
//!
//! **Nothing the guest writes comes back.** The filesystem is an initramfs held
//! in the VM's memory and discarded on reset. The workspace is copied in;
//! changes are not copied out. That is why no snapshot or fork support is
//! declared, and it is the honest shape for what this backend is for: running
//! code you do not trust and keeping its output.
//!
//! # What it needs
//!
//! `firecracker`, a statically linked `busybox`, an uncompressed guest kernel,
//! and a readable `/dev/kvm`.
//!
//! ```sh
//! # A kernel and the hypervisor, from Firecracker's own CI artifacts.
//! curl -L -o vmlinux \
//!   https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.12/x86_64/vmlinux-6.1.128
//! curl -L https://github.com/firecracker-microvm/firecracker/releases/latest/download/\
//! firecracker-v1.16.1-x86_64.tgz | tar -xz
//! ```

mod cpio;
mod sandbox;

pub use sandbox::{GuestImage, MicroVmSandbox, NAME, WORKSPACE_MOUNT};
