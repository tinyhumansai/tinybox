//! The `tinybox` command-line interface.
//!
//! One of two adapters over [`tinybox_core`] — the other is the `TinyBus` module
//! — so everything here is argument parsing, dispatch, and rendering. Behavior
//! belongs in core, where both adapters can reach it.
//!
//! # What this build can do
//!
//! Only the passthrough sandbox on the local host, which means boxes that run
//! commands with the launching user's full privileges. `tinybox create` prints
//! that warning rather than leaving the reader to infer it from the isolation
//! level.
//!
//! # State
//!
//! `create` and `exec` are separate processes, so box records live in a JSON
//! file — see [`FileStore`]. Point `TINYBOX_STATE_DIR` somewhere else to keep a
//! run self-contained.

mod command;
mod store;

pub use command::{Cli, run, run_with_host};
pub use store::FileStore;
