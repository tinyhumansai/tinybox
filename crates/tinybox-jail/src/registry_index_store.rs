//! Persistence contract for a registry's serialized index.

use std::io;

/// Persistence for the registry's serialized index.
///
/// The registry owns the index shape and serializes it; a host supplies the
/// persistence adapter. This keeps filesystem and document backends outside
/// the jail library.
pub trait IndexStore: Send + Sync + std::fmt::Debug + 'static {
    /// The stored index, or `None` when nothing was written yet.
    ///
    /// # Errors
    /// Returns an error when the index exists but cannot be read.
    fn load(&self) -> io::Result<Option<Vec<u8>>>;

    /// Replace the stored index with `bytes`.
    ///
    /// # Errors
    /// Returns an error when the index cannot be persisted.
    fn save(&self, bytes: &[u8]) -> io::Result<()>;
}
