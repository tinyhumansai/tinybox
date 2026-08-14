//! Reading and writing the small JSON documents tinybox keeps on disk.
//!
//! The box store and the template index are the same shape — one JSON map, read
//! whole, written whole — and were the same twenty lines of error handling
//! twice. They share this instead, so there is one place that decides how a
//! tinybox document is read, written, and reported on when it goes wrong.

use std::fs;
use std::path::Path;

use serde::Serialize;
use serde::de::DeserializeOwned;
use tinybox_core::{Error, Result};

/// Read and parse a document.
///
/// A missing file is an empty document rather than an error: that is what makes
/// a fresh install work without an initialization step.
///
/// # Errors
///
/// Returns [`Error::Store`] when the file exists but cannot be read or parsed.
/// An unreadable document is never treated as empty — doing so would silently
/// orphan everything it described.
pub(crate) fn read<T: DeserializeOwned + Default>(path: &Path, describes: &str) -> Result<T> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(T::default()),
        Err(error) => return Err(failed("read", &error)),
    };

    serde_json::from_str(&text).map_err(|error| Error::Store {
        operation: "parse",
        message: format!("{} is not a valid {describes}: {error}", path.display()),
    })
}

/// Wrap a failure that has nothing more to say than what went wrong.
///
/// Every step of a write reports the same shape, and spelling the struct out
/// each time buried the sequence in four times as much error handling as
/// actual work.
fn failed(operation: &'static str, error: &impl std::fmt::Display) -> Error {
    Error::Store {
        operation,
        message: error.to_string(),
    }
}

/// Replace a document atomically.
///
/// Writes a sibling temporary file and renames it over the target, so a
/// concurrent reader sees either the old document or the new one and never a
/// half-written one. The temporary file must share a directory with the target
/// for the rename to stay within a single filesystem.
///
/// # Errors
///
/// Returns [`Error::Store`] when the parent directory cannot be created, or the
/// document cannot be encoded, written, or renamed into place.
pub(crate) fn write<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let parent = path.parent().ok_or_else(|| Error::Store {
        operation: "write",
        message: format!("{} has no parent directory", path.display()),
    })?;
    fs::create_dir_all(parent).map_err(|error| failed("create", &error))?;

    let text = serde_json::to_string_pretty(value).map_err(|error| failed("encode", &error))?;

    let temporary = path.with_extension("json.tmp");
    fs::write(&temporary, text).map_err(|error| failed("write", &error))?;
    fs::rename(&temporary, path).map_err(|error| failed("rename", &error))
}

#[cfg(test)]
mod test;
