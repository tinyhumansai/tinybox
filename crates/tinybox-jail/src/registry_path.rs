//! Resolve missing registry children without mixing lexical and canonical paths.

use std::io;
use std::path::{Component, Path, PathBuf};

/// Canonicalize the existing ancestor and append missing normal components.
/// Never treat a dangling symlink or an access failure as a missing directory.
pub(super) fn canonicalize_missing(path: &Path) -> io::Result<PathBuf> {
    if path
        .components()
        .any(|part| matches!(part, Component::ParentDir))
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "registry paths must not contain parent traversal",
        ));
    }
    let mut ancestor = path.to_path_buf();
    let mut missing = Vec::new();
    loop {
        match ancestor.canonicalize() {
            Ok(resolved) => return append_missing(resolved, &missing),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                match std::fs::symlink_metadata(&ancestor) {
                    Ok(_) => return Err(error),
                    Err(metadata_error) if metadata_error.kind() == io::ErrorKind::NotFound => {}
                    Err(metadata_error) => return Err(metadata_error),
                }
                let Some(part) = ancestor.file_name() else {
                    return Err(error);
                };
                missing.push(part.to_os_string());
                ancestor.pop();
                if ancestor.as_os_str().is_empty() {
                    ancestor.push(".");
                }
            }
            Err(error) => return Err(error),
        }
    }
}

/// Missing child components require an existing directory, never a file.
fn append_missing(mut resolved: PathBuf, missing: &[std::ffi::OsString]) -> io::Result<PathBuf> {
    if !missing.is_empty() && !resolved.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotADirectory,
            "missing jail path has a non-directory ancestor",
        ));
    }
    for part in missing.iter().rev() {
        resolved.push(part);
    }
    Ok(resolved)
}

#[cfg(test)]
#[path = "registry_path_tests.rs"]
mod tests;
