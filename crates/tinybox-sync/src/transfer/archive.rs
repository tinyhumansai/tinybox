//! Packing a workspace into a tar stream.

use std::fs;
use std::path::Path;

use tinybox_core::{Error, Result};

use crate::fingerprint::{Fingerprint, entries};

use super::MARKER;

/// Pack `root` into an uncompressed tar archive, with the fingerprint inside.
///
/// The marker is written as part of the same archive rather than by a second
/// command, so it cannot end up describing a tree that was never fully
/// unpacked: either the whole archive lands or none of it does.
///
/// The archive is uncompressed. Compression would trade CPU on both ends for
/// bandwidth, which is the wrong trade for the common case of a machine on the
/// same network — and the expensive transfers are already the ones the
/// fingerprint skips entirely.
///
/// # Errors
///
/// Returns [`Error::Io`] when the tree cannot be read, or when a file changes
/// size while it is being packed.
pub(super) fn pack(root: &Path, exclude: &[String], fingerprint: &Fingerprint) -> Result<Vec<u8>> {
    let mut builder = tar::Builder::new(Vec::new());
    // Reproducible archives: no unstable metadata, so packing the same tree
    // twice yields the same bytes.
    builder.mode(tar::HeaderMode::Deterministic);

    for entry in entries(root, exclude)? {
        let contents = fs::read(root.join(&entry.path))
            .map_err(|error| Error::io("read a workspace file", &error))?;
        append(&mut builder, &entry.path, &contents, entry.executable)?;
    }

    // Part of the same archive rather than a second command, so the marker
    // cannot end up describing a tree that was never fully unpacked: either the
    // whole archive lands or none of it does.
    append(
        &mut builder,
        Path::new(MARKER),
        format!("{fingerprint}\n").as_bytes(),
        false,
    )?;

    builder
        .into_inner()
        .map_err(|error| Error::io("finish the workspace archive", &error))
}

/// Add one file to the archive with a fixed, reproducible header.
///
/// Both the workspace files and the fingerprint marker go through here, so
/// there is one place that decides what a tinybox archive entry looks like.
fn append(
    builder: &mut tar::Builder<Vec<u8>>,
    path: &Path,
    contents: &[u8],
    executable: bool,
) -> Result<()> {
    let mut header = tar::Header::new_gnu();
    header.set_size(contents.len() as u64);
    header.set_mode(if executable { 0o755 } else { 0o644 });
    header.set_mtime(0);
    header.set_entry_type(tar::EntryType::Regular);
    header.set_cksum();

    builder
        .append_data(&mut header, path, contents)
        .map_err(|error| Error::io("pack a workspace file", &error))
}
