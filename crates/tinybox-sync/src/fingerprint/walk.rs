//! Walking a workspace tree in a reproducible order.

use std::fs;
use std::path::Path;

use tinybox_core::{Error, Result};

use super::Entry;

/// Every regular file under `root`, sorted by relative path.
///
/// Sorting is the point: directory iteration order is not stable across
/// filesystems or even between runs, and an unstable order would produce an
/// unstable fingerprint that reports a change on every run.
///
/// Symbolic links are skipped rather than followed. Following them risks
/// leaving the tree entirely — a link to `/etc` would pull the host's
/// configuration into the transfer — and can loop forever on a cycle.
///
/// # Errors
///
/// Returns [`Error::Io`] when `root` or a directory beneath it cannot be read.
pub(crate) fn entries(root: &Path, exclude: &[String]) -> Result<Vec<Entry>> {
    let mut found = Vec::new();
    collect(root, Path::new(""), exclude, &mut found)?;
    found.sort();
    Ok(found)
}

/// Recurse into one directory, accumulating its files.
fn collect(root: &Path, relative: &Path, exclude: &[String], found: &mut Vec<Entry>) -> Result<()> {
    let directory = root.join(relative);
    let listing = fs::read_dir(&directory)
        .map_err(|error| Error::io("read a workspace directory", &error))?;

    for entry in listing {
        let entry = entry.map_err(|error| Error::io("read a workspace directory", &error))?;
        let name = entry.file_name();

        if exclude.iter().any(|excluded| excluded.as_str() == name) {
            continue;
        }

        let child = relative.join(&name);
        // `file_type` does not follow links, which is what lets a link be
        // recognized and skipped rather than silently traversed.
        let kind = entry
            .file_type()
            .map_err(|error| Error::io("inspect a workspace entry", &error))?;

        if kind.is_dir() {
            collect(root, &child, exclude, found)?;
        } else if kind.is_file() {
            let metadata = entry
                .metadata()
                .map_err(|error| Error::io("inspect a workspace file", &error))?;
            found.push(Entry {
                path: child,
                executable: is_executable(&metadata),
            });
        }
        // Anything else — a symlink, a socket, a device — is skipped. None of
        // them can be reproduced faithfully on the far side, and pretending
        // otherwise would make the fingerprint claim more than it can.
    }
    Ok(())
}

/// Whether the owner execute bit is set.
///
/// The full permission set is not carried: a workspace arriving with a
/// different umask is normal, while a script arriving without its execute bit
/// is broken. Only the bit that changes behavior is preserved.
#[cfg(unix)]
fn is_executable(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    metadata.permissions().mode() & 0o100 != 0
}

/// Whether the file is executable.
///
/// Windows has no execute bit, so every file reports the same value and the
/// fingerprint simply does not distinguish on it.
#[cfg(not(unix))]
fn is_executable(_metadata: &fs::Metadata) -> bool {
    false
}
