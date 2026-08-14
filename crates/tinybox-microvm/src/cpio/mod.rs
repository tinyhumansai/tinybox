//! Writing the `newc` cpio archives a Linux kernel unpacks as an initramfs.
//!
//! Every microVM here boots from an initramfs built for that one box: it holds
//! the guest's `init`, a static `busybox`, and the workspace. There is no
//! disk image, which is what keeps a boot down to under a second.
//!
//! # Why this is written out rather than shelled out to `cpio`
//!
//! It is the one place in tinybox that builds a binary format by hand, and the
//! reason is that `newc` is small enough to be worth it: fixed 110-byte ASCII
//! headers, hexadecimal fields, four-byte alignment. Around a hundred lines,
//! entirely pure, and every field assertable in a test — whereas piping a
//! directory through `cpio(1)` would mean materializing the whole guest tree on
//! disk first, and depending on yet another tool being installed.

use std::fmt::Write as _;

use tinybox_core::{Error, Result};

use crate::NAME;

mod entry;

pub(crate) use entry::{Entry, Kind};

/// The `newc` magic every header starts with.
const MAGIC: &str = "070701";

/// The name that terminates an archive.
const TRAILER: &str = "TRAILER!!!";

/// Build a `newc` archive from `entries`.
///
/// Entries are written in the order given, which matters: a file must not
/// appear before the directory that contains it, or the kernel has nowhere to
/// put it.
///
/// # Errors
///
/// Returns [`Error::Backend`] when an entry does not fit the format: every
/// header field is eight hexadecimal digits, so a file of 4 GiB or more, or a
/// path that long, cannot be described. Refusing matters more here than
/// elsewhere, because a truncated field is not a corrupt file — it is a valid
/// header with the wrong length, and the kernel would read the next entry from
/// the middle of this one and see the archive end early.
pub(crate) fn archive(entries: &[Entry]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        // Inode numbers only have to be distinct within the archive; the
        // position in the list is the simplest thing that guarantees it. An
        // archive with four billion entries would not fit in memory first.
        let inode = u32::try_from(index + 1).unwrap_or(u32::MAX);
        write_entry(&mut out, entry, inode)?;
    }
    write_trailer(&mut out)?;
    Ok(out)
}

/// Reject a length the `newc` format cannot express.
fn checked_len(value: usize, what: &str, path: &str) -> Result<u32> {
    u32::try_from(value).map_err(|_| Error::Backend {
        sandbox: NAME.to_owned(),
        operation: "build the guest filesystem",
        message: format!("{path}: the {what} is {value} bytes and the cpio format allows 4 GiB"),
    })
}

/// Append one entry, header and contents.
fn write_entry(out: &mut Vec<u8>, entry: &Entry, inode: u32) -> Result<()> {
    let name = entry.path.as_bytes();
    let body = entry.body();
    let size = checked_len(body.len(), "contents", &entry.path)?;
    let namesize = checked_len(name.len() + 1, "path", &entry.path)?;

    // A `newc` header is thirteen 8-digit hexadecimal fields after the magic,
    // in a fixed order, with no separators.
    let mut header = String::with_capacity(110);
    header.push_str(MAGIC);
    for field in [
        inode,
        entry.mode(),
        0, // uid: everything belongs to root inside the guest
        0, // gid
        1, // nlink
        0, // mtime: zero, so the same inputs produce the same archive
        size,
        0,        // devmajor
        0,        // devminor
        0,        // rdevmajor
        0,        // rdevminor
        namesize, // counting the terminator
        0,        // check: unused by the `newc` format
    ] {
        let _ = write!(header, "{field:08x}");
    }

    out.extend_from_slice(header.as_bytes());
    out.extend_from_slice(name);
    out.push(0);
    pad(out);

    out.extend_from_slice(body);
    pad(out);
    Ok(())
}

/// Append the trailer that tells the kernel the archive has ended.
fn write_trailer(out: &mut Vec<u8>) -> Result<()> {
    write_entry(
        out,
        &Entry {
            path: TRAILER.to_owned(),
            kind: Kind::File {
                contents: Vec::new(),
                executable: false,
            },
        },
        0,
    )
}

/// Pad to the next four-byte boundary.
///
/// Both the name and the body are aligned this way. Getting it wrong does not
/// fail loudly — the kernel reads the next header from the wrong offset and the
/// archive simply appears to end early.
fn pad(out: &mut Vec<u8>) {
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
}

#[cfg(test)]
mod test;
