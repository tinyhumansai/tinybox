//! Deciding whether a workspace has changed since it was last sent.
//!
//! The expensive part of running code on another machine is moving the code
//! there, and in an edit-run loop most runs change nothing. A fingerprint makes
//! that check cheap: hash the tree, compare with what the far side already has,
//! and transfer only on a difference.
//!
//! # What is hashed
//!
//! Every file's relative path, its executable bit, and its contents, folded
//! together in sorted path order. Sorting is what makes the result reproducible
//! — directory iteration order is not stable across filesystems, and an
//! unstable fingerprint would report a change on every run and defeat the whole
//! point.
//!
//! Modification times are deliberately **not** hashed. A checkout, a rebase, or
//! a `touch` changes them without changing the content, and treating that as a
//! change would resend an identical tree.
//!
//! ```no_run
//! use tinybox_sync::{Exclusions, Fingerprint};
//!
//! let exclude = Exclusions::read("/srv/work")?;
//! let before = Fingerprint::of_directory("/srv/work", &exclude)?;
//! // ... no edits ...
//! let after = Fingerprint::of_directory("/srv/work", &exclude)?;
//! assert_eq!(before, after);
//! # Ok::<(), tinybox_core::Error>(())
//! ```

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use tinybox_core::{Error, Result};

use crate::exclude::Exclusions;

mod walk;

pub(crate) use walk::entries;

/// The content identity of a workspace tree.
///
/// Two trees with the same fingerprint have the same files with the same
/// contents and the same executable bits, whatever their timestamps.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Fingerprint(String);

impl Fingerprint {
    /// Hash the tree rooted at `root`, skipping whatever `exclude` covers.
    ///
    /// The exclusions are part of the identity: two runs that exclude different
    /// things are describing different trees, and must not be mistaken for the
    /// same one.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] when `root` cannot be read, or when a file
    /// disappears or becomes unreadable while the tree is being walked.
    pub fn of_directory(root: impl AsRef<Path>, exclude: &Exclusions) -> Result<Self> {
        let root = root.as_ref();
        let mut hasher = blake3::Hasher::new();

        for entry in entries(root, exclude)? {
            let contents = fs::read(root.join(&entry.path))
                .map_err(|error| Error::io("read a workspace file", &error))?;

            // Length-prefixing each field keeps two different trees from
            // hashing the same way: without it, a file `ab` next to `c` and a
            // file `a` next to `bc` would fold into identical bytes.
            hash_field(&mut hasher, entry.path.to_string_lossy().as_bytes());
            hash_field(&mut hasher, &[u8::from(entry.executable)]);
            hash_field(&mut hasher, &contents);
        }

        Ok(Self(hasher.finalize().to_hex().to_string()))
    }

    /// Read a fingerprint that was written by [`Fingerprint::as_str`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidIdentifier`] when `value` is not a hex digest,
    /// which is what a truncated or hand-edited marker file looks like. Failing
    /// here means an unrecognizable marker causes a resend rather than a
    /// wrongly skipped one.
    pub fn parse(value: &str) -> Result<Self> {
        let value = value.trim();
        if value.len() != DIGEST_LENGTH || !value.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(Error::InvalidIdentifier {
                kind: "workspace fingerprint",
                value: value.to_owned(),
            });
        }
        Ok(Self(value.to_owned()))
    }

    /// The digest as text, suitable for writing to a marker file.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A blake3 digest rendered as hex.
const DIGEST_LENGTH: usize = 64;

/// Fold one length-prefixed field into the hash.
fn hash_field(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// One file in a workspace tree.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Entry {
    /// The path relative to the tree root.
    pub(crate) path: PathBuf,
    /// Whether the owner execute bit is set, which is the only permission that
    /// changes how a file behaves once it arrives.
    pub(crate) executable: bool,
}

#[cfg(test)]
mod test;
