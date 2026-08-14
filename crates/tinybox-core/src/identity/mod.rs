//! Validated names for boxes, snapshots, and providers.
//!
//! Every identifier tinybox accepts ends up somewhere hostile to free-form
//! text: a filesystem path under the box store, a container name, an SSH
//! command line, a `TinyBus` object path. Validating once at construction
//! means the rest of the crate can pass these around without re-checking or
//! quoting.
//!
//! ```
//! use tinybox_core::identity::BoxId;
//!
//! let id = BoxId::new("build-7f3a")?;
//! assert_eq!(id.as_str(), "build-7f3a");
//!
//! assert!(BoxId::new("../escape").is_err());
//! assert!(BoxId::new("").is_err());
//! # Ok::<(), tinybox_core::Error>(())
//! ```

use crate::error::{Error, Result};

mod types;

pub use types::{BoxId, HostRef, SandboxRef, SnapshotId};

/// Whether `value` would be accepted as a tinybox identifier.
///
/// Backends sometimes need to validate a name that is not one of the newtypes
/// here — a Docker namespace, say — against the same rule, and duplicating the
/// character set is how the two drift apart.
#[must_use]
pub fn is_valid(value: &str) -> bool {
    validate("identifier", value).is_ok()
}

/// The longest identifier tinybox accepts.
///
/// Container runtimes and filesystem layouts both tolerate far more than this,
/// but a short ceiling keeps identifiers readable in logs and leaves room for
/// the suffixes the store appends.
const MAX_LENGTH: usize = 64;

/// Validate free-form text for use as an identifier.
///
/// Accepts a non-empty string of at most [`MAX_LENGTH`] characters drawn from
/// `[A-Za-z0-9._-]`, which is the intersection of what a path component, a
/// container name, and a shell word all accept without quoting. The set
/// deliberately excludes `/` and `.` runs that could traverse a directory.
///
/// # Errors
///
/// Returns [`Error::InvalidIdentifier`] describing `kind` when `value` is
/// empty, too long, contains a character outside the permitted set, or is a
/// relative path component such as `.` or `..`.
fn validate(kind: &'static str, value: &str) -> Result<()> {
    let invalid = || Error::InvalidIdentifier {
        kind,
        value: value.to_owned(),
    };

    if value.is_empty() || value.len() > MAX_LENGTH {
        return Err(invalid());
    }
    if value == "." || value == ".." {
        return Err(invalid());
    }
    if !value
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-'))
    {
        return Err(invalid());
    }
    Ok(())
}

#[cfg(test)]
mod test;
