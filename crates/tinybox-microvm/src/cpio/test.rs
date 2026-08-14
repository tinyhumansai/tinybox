//! Tests for the cpio writer.
//!
//! A malformed archive does not fail loudly — the kernel reads the next header
//! from the wrong offset and the initramfs simply appears to end early, which
//! surfaces much later as a guest that will not boot. So the format is pinned
//! field by field here, and `live_microvm.rs` boots one for real.

use tinybox_core::Result;

use super::{Entry, archive, checked_len};

/// The fixed size of a `newc` header before the name.
const HEADER: usize = 110;

/// Read one 8-digit hexadecimal header field by index.
fn field(bytes: &[u8], index: usize) -> u32 {
    let start = 6 + index * 8;
    let text = std::str::from_utf8(&bytes[start..start + 8]).unwrap_or("00000000");
    u32::from_str_radix(text, 16).unwrap_or_default()
}

#[test]
fn an_archive_starts_with_the_newc_magic() -> Result<()> {
    let bytes = archive(&[Entry::file("hello", "hi")])?;

    assert_eq!(&bytes[..6], b"070701");
    Ok(())
}

#[test]
fn a_header_records_the_size_and_name_length() -> Result<()> {
    let bytes = archive(&[Entry::file("hello", "abcd")])?;

    // Field 6 is the body size, field 11 the name length including its
    // terminator. Both are what the kernel uses to find the next header.
    assert_eq!(field(&bytes, 6), 4);
    assert_eq!(
        field(&bytes, 11),
        u32::try_from("hello".len() + 1).unwrap_or_default()
    );
    Ok(())
}

#[test]
fn the_name_follows_the_header_and_is_terminated() -> Result<()> {
    let bytes = archive(&[Entry::file("hello", "hi")])?;

    assert_eq!(&bytes[HEADER..HEADER + 5], b"hello");
    assert_eq!(bytes[HEADER + 5], 0);
    Ok(())
}

#[test]
fn a_directory_and_a_file_carry_different_modes() -> Result<()> {
    let directory = archive(&[Entry::directory("bin")])?;
    let file = archive(&[Entry::file("note", "x")])?;
    let program = archive(&[Entry::program("init", "#!/bin/sh\n")])?;

    // The high bits are the file type: without them the kernel creates the
    // wrong kind of thing and the guest cannot boot.
    assert_eq!(field(&directory, 1), 0o040_755);
    assert_eq!(field(&file, 1), 0o100_644);
    assert_eq!(field(&program, 1), 0o100_755);
    Ok(())
}

#[test]
fn a_directory_contributes_no_body() -> Result<()> {
    let bytes = archive(&[Entry::directory("proc")])?;

    assert_eq!(field(&bytes, 6), 0);
    Ok(())
}

#[test]
fn everything_is_owned_by_root_inside_the_guest() -> Result<()> {
    let bytes = archive(&[Entry::file("note", "x")])?;

    // uid and gid. The guest runs as root in its own VM, and a file owned by
    // the host's uid would be unreadable there.
    assert_eq!(field(&bytes, 2), 0);
    assert_eq!(field(&bytes, 3), 0);
    Ok(())
}

#[test]
fn entries_are_padded_to_four_byte_boundaries() -> Result<()> {
    // A name and a body of awkward lengths, so both paddings are exercised.
    let bytes = archive(&[Entry::file("a", "bcd"), Entry::file("ee", "f")])?;

    assert_eq!(bytes.len() % 4, 0);
    // The second header must begin on a boundary, and begin with the magic.
    let second = bytes
        .windows(6)
        .enumerate()
        .filter(|(offset, window)| *offset > 0 && *window == b"070701")
        .map(|(offset, _)| offset)
        .next();
    assert_eq!(second.map(|offset| offset % 4), Some(0));
    Ok(())
}

#[test]
fn inode_numbers_are_distinct() -> Result<()> {
    let bytes = archive(&[Entry::file("a", "1"), Entry::file("b", "2")])?;

    let headers = bytes
        .windows(6)
        .enumerate()
        .filter(|(_, window)| *window == b"070701")
        .map(|(offset, _)| field(&bytes[offset..], 0))
        .collect::<Vec<_>>();

    // Two entries plus the trailer. The first two must differ; the kernel uses
    // the inode number to detect hard links, and repeating one would make the
    // second file an alias of the first.
    assert_ne!(headers[0], headers[1]);
    Ok(())
}

#[test]
fn an_archive_ends_with_the_trailer() -> Result<()> {
    let bytes = archive(&[Entry::file("note", "x")])?;

    let text = String::from_utf8_lossy(&bytes);
    assert!(text.contains("TRAILER!!!"));
    // Nothing may follow it but padding.
    let after = text.rfind("TRAILER!!!").unwrap_or(0) + "TRAILER!!!".len();
    assert!(bytes[after..].iter().all(|byte| *byte == 0));
    Ok(())
}

#[test]
fn the_same_input_produces_the_same_archive() {
    let entries = [
        Entry::directory("bin"),
        Entry::program("init", "#!/bin/sh\n"),
        Entry::file("workspace/note", "hello"),
    ];

    // No timestamps and no host uids, so a box built from identical inputs
    // boots an identical guest.
    assert_eq!(archive(&entries), archive(&entries));
}

#[test]
fn binary_contents_survive_intact() -> Result<()> {
    let payload: Vec<u8> = (0u8..=255).collect();
    let bytes = archive(&[Entry::file("blob", payload.clone())])?;

    // busybox is a binary, so a writer that mangled bytes would produce an
    // archive that unpacks into an unusable guest.
    assert!(
        bytes
            .windows(payload.len())
            .any(|window| window == payload.as_slice())
    );
    Ok(())
}

#[test]
fn an_empty_archive_is_still_valid() -> Result<()> {
    let bytes = archive(&[])?;

    assert_eq!(&bytes[..6], b"070701");
    assert!(String::from_utf8_lossy(&bytes).contains("TRAILER!!!"));
    Ok(())
}

#[test]
fn a_length_the_format_cannot_express_is_refused() {
    // Every header field is eight hexadecimal digits. Truncating one would not
    // produce a corrupt file — it would produce a valid header with the wrong
    // length, and the kernel would read the following entry out of the middle
    // of this one. Tested directly because the alternative is allocating 4 GiB.
    let refused = checked_len(usize::MAX, "contents", "huge.bin");

    let message = refused
        .err()
        .map(|error| error.to_string())
        .unwrap_or_default();
    assert!(message.contains("huge.bin"), "{message}");
    assert!(message.contains("4 GiB"), "{message}");
}

#[test]
fn a_length_the_format_can_express_is_accepted() {
    assert_eq!(checked_len(1234, "contents", "note.txt").ok(), Some(1234));
}
