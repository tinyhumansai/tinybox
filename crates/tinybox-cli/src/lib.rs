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
//! The CLI library receives its [`tinybox_core::Store`] and
//! [`tinybox_core::Templates`] from a host composition root. The `tinybox`
//! executable chooses a local document engine and imports the previous JSON
//! state files before dispatch.

mod command;

pub use command::Cli;

#[cfg(test)]
pub use command::{run, run_with_host};
