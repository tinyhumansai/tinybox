//! Fingerprinting and transferring a tinybox workspace.
//!
//! Running code on another machine costs whatever it costs to move the code
//! there, and in an edit-run loop most runs change nothing. [`Fingerprint`]
//! makes that check cheap, and [`Syncer`] acts on it: a repeated sync with no
//! edits sends zero bytes.
//!
//! ```no_run
//! use std::sync::Arc;
//! use tinybox_host::LocalHost;
//! use tinybox_sync::Syncer;
//!
//! # async fn run() -> tinybox_core::Result<()> {
//! let syncer = Syncer::new(Arc::new(LocalHost::new())).excluding([".git", "target"]);
//!
//! let first = syncer.sync("/srv/work", "/tmp/work").await?;
//! assert!(first.transferred());
//!
//! // Nothing changed in between, so nothing crosses.
//! let second = syncer.sync("/srv/work", "/tmp/work").await?;
//! assert!(!second.transferred());
//! # Ok(())
//! # }
//! ```
//!
//! # What the far side needs
//!
//! `tar` and `mkdir`, and nothing else. The archive is built in this process
//! and piped over, so there is no rsync requirement and no tinybox agent to
//! install — which matters because the far side is often a container image
//! somebody else built.
//!
//! # What this is not
//!
//! Whole-tree transfer with a skip, not a per-file delta. When a tree does
//! change, all of it is sent. A real delta needs rsync's rolling checksum or an
//! agent on the far side to negotiate with; the skip is the win that matters
//! for an edit-run loop, and it is the one available without either.

mod fingerprint;
mod transfer;

pub use fingerprint::Fingerprint;
pub use transfer::{MARKER, Sync, Syncer, default_destination};
