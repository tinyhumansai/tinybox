//! Tests for workspace fingerprinting.

use std::fs;
use std::path::Path;

use tempfile::TempDir;
use tinybox_core::{Error, Result};

use super::Fingerprint;
use crate::exclude::Exclusions;

fn temp_dir() -> Result<TempDir> {
    TempDir::new().map_err(|error| Error::io("tempdir", &error))
}

/// Write `contents` to `path` under `root`, creating parents as needed.
fn write(root: &Path, path: &str, contents: &str) -> Result<()> {
    let full = root.join(path);
    if let Some(parent) = full.parent() {
        fs::create_dir_all(parent).map_err(|error| Error::io("mkdir", &error))?;
    }
    fs::write(&full, contents).map_err(|error| Error::io("write", &error))
}

/// A small tree with a nested directory.
fn tree() -> Result<TempDir> {
    let dir = temp_dir()?;
    write(dir.path(), "a.txt", "alpha")?;
    write(dir.path(), "nested/b.txt", "beta")?;
    Ok(dir)
}

#[test]
fn the_same_tree_hashes_the_same_way_twice() -> Result<()> {
    let dir = tree()?;

    // If this were unstable, every run would report a change and no transfer
    // would ever be skipped.
    assert_eq!(
        Fingerprint::of_directory(dir.path(), &Exclusions::none())?,
        Fingerprint::of_directory(dir.path(), &Exclusions::none())?
    );
    Ok(())
}

#[test]
fn two_trees_with_identical_content_agree() -> Result<()> {
    let one = tree()?;
    let other = tree()?;

    // Different directories, same content: the fingerprint is about the tree,
    // not about where it happens to live.
    assert_eq!(
        Fingerprint::of_directory(one.path(), &Exclusions::none())?,
        Fingerprint::of_directory(other.path(), &Exclusions::none())?
    );
    Ok(())
}

#[test]
fn changing_a_file_changes_the_fingerprint() -> Result<()> {
    let dir = tree()?;
    let before = Fingerprint::of_directory(dir.path(), &Exclusions::none())?;

    write(dir.path(), "a.txt", "changed")?;

    assert_ne!(
        Fingerprint::of_directory(dir.path(), &Exclusions::none())?,
        before
    );
    Ok(())
}

#[test]
fn adding_or_removing_a_file_changes_the_fingerprint() -> Result<()> {
    let dir = tree()?;
    let before = Fingerprint::of_directory(dir.path(), &Exclusions::none())?;

    write(dir.path(), "c.txt", "gamma")?;
    let with_extra = Fingerprint::of_directory(dir.path(), &Exclusions::none())?;
    assert_ne!(with_extra, before);

    fs::remove_file(dir.path().join("c.txt")).map_err(|error| Error::io("remove", &error))?;
    assert_eq!(
        Fingerprint::of_directory(dir.path(), &Exclusions::none())?,
        before
    );
    Ok(())
}

#[test]
fn renaming_a_file_changes_the_fingerprint() -> Result<()> {
    let dir = temp_dir()?;
    write(dir.path(), "before.txt", "same content")?;
    let before = Fingerprint::of_directory(dir.path(), &Exclusions::none())?;

    fs::rename(dir.path().join("before.txt"), dir.path().join("after.txt"))
        .map_err(|error| Error::io("rename", &error))?;

    // The path is hashed, not just the bytes.
    assert_ne!(
        Fingerprint::of_directory(dir.path(), &Exclusions::none())?,
        before
    );
    Ok(())
}

#[test]
fn content_cannot_be_shuffled_between_files_unnoticed() -> Result<()> {
    // Without length-prefixed fields, `ab` next to `c` and `a` next to `bc`
    // would fold into the same bytes and hash identically.
    let one = temp_dir()?;
    write(one.path(), "f1", "ab")?;
    write(one.path(), "f2", "c")?;

    let other = temp_dir()?;
    write(other.path(), "f1", "a")?;
    write(other.path(), "f2", "bc")?;

    assert_ne!(
        Fingerprint::of_directory(one.path(), &Exclusions::none())?,
        Fingerprint::of_directory(other.path(), &Exclusions::none())?
    );
    Ok(())
}

#[test]
fn a_touched_file_is_not_a_changed_file() -> Result<()> {
    let dir = tree()?;
    let before = Fingerprint::of_directory(dir.path(), &Exclusions::none())?;

    // Rewriting identical content updates the modification time. A checkout or
    // a rebase does the same thing across a whole tree, and treating that as a
    // change would resend an identical workspace.
    write(dir.path(), "a.txt", "alpha")?;

    assert_eq!(
        Fingerprint::of_directory(dir.path(), &Exclusions::none())?,
        before
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn making_a_file_executable_changes_the_fingerprint() -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = temp_dir()?;
    write(dir.path(), "run.sh", "#!/bin/sh\n")?;
    let before = Fingerprint::of_directory(dir.path(), &Exclusions::none())?;

    // A script arriving without its execute bit is broken, so the bit is part
    // of the tree's identity.
    fs::set_permissions(dir.path().join("run.sh"), fs::Permissions::from_mode(0o755))
        .map_err(|error| Error::io("chmod", &error))?;

    assert_ne!(
        Fingerprint::of_directory(dir.path(), &Exclusions::none())?,
        before
    );
    Ok(())
}

#[test]
fn an_excluded_directory_does_not_affect_the_fingerprint() -> Result<()> {
    let dir = tree()?;
    write(dir.path(), ".gitignore", ".git/\n")?;
    let exclude = Exclusions::read(dir.path())?;
    let before = Fingerprint::of_directory(dir.path(), &exclude)?;

    write(dir.path(), ".git/HEAD", "ref: refs/heads/main")?;
    write(dir.path(), "nested/.git/HEAD", "ref: refs/heads/other")?;

    // An unanchored rule matches at any depth, so the nested one goes too.
    assert_eq!(Fingerprint::of_directory(dir.path(), &exclude)?, before);
    // ...and without the exclusion it would have changed.
    assert_ne!(
        Fingerprint::of_directory(dir.path(), &Exclusions::none())?,
        before
    );
    Ok(())
}

#[test]
fn the_exclusions_are_part_of_the_identity() -> Result<()> {
    let dir = tree()?;
    write(dir.path(), ".gitignore", "nested/\n")?;

    let everything = Fingerprint::of_directory(dir.path(), &Exclusions::none())?;
    let filtered = Fingerprint::of_directory(dir.path(), &Exclusions::read(dir.path())?)?;

    // Two runs excluding different things describe different trees, and must
    // not be mistaken for the same one — otherwise changing an ignore rule
    // would leave a stale workspace on the far side.
    assert_ne!(everything, filtered);
    Ok(())
}

#[test]
fn an_empty_directory_is_ignored() -> Result<()> {
    let dir = tree()?;
    let before = Fingerprint::of_directory(dir.path(), &Exclusions::none())?;

    fs::create_dir(dir.path().join("empty")).map_err(|error| Error::io("mkdir", &error))?;

    // Tar carries files; an empty directory has nothing to send and nothing to
    // compare, so it does not move the fingerprint.
    assert_eq!(
        Fingerprint::of_directory(dir.path(), &Exclusions::none())?,
        before
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn a_symbolic_link_is_skipped_rather_than_followed() -> Result<()> {
    let dir = tree()?;
    let before = Fingerprint::of_directory(dir.path(), &Exclusions::none())?;

    // Following this would pull the host's password file into the workspace.
    std::os::unix::fs::symlink("/etc/passwd", dir.path().join("leak"))
        .map_err(|error| Error::io("symlink", &error))?;

    assert_eq!(
        Fingerprint::of_directory(dir.path(), &Exclusions::none())?,
        before
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn a_link_cycle_does_not_hang_the_walk() -> Result<()> {
    let dir = temp_dir()?;
    write(dir.path(), "a.txt", "alpha")?;
    std::os::unix::fs::symlink(dir.path(), dir.path().join("loop"))
        .map_err(|error| Error::io("symlink", &error))?;

    // Following links would recurse forever here.
    assert!(Fingerprint::of_directory(dir.path(), &Exclusions::none()).is_ok());
    Ok(())
}

#[test]
fn an_unreadable_root_is_reported() {
    assert!(matches!(
        Fingerprint::of_directory("/tinybox-no-such-directory", &Exclusions::none()),
        Err(Error::Io { .. })
    ));
}

#[test]
fn a_fingerprint_round_trips_through_text() -> Result<()> {
    let dir = tree()?;
    let fingerprint = Fingerprint::of_directory(dir.path(), &Exclusions::none())?;

    assert_eq!(Fingerprint::parse(fingerprint.as_str())?, fingerprint);
    // A marker file arrives with a trailing newline.
    assert_eq!(
        Fingerprint::parse(&format!("{fingerprint}\n"))?,
        fingerprint
    );
    assert_eq!(fingerprint.to_string(), fingerprint.as_str());
    Ok(())
}

#[test]
fn an_unrecognizable_marker_is_rejected_so_the_tree_is_resent() {
    // Accepting one of these would risk skipping a transfer that should have
    // happened, which is the one failure mode that matters here.
    for bad in [
        "",
        "not-a-digest",
        &"a".repeat(63),
        &"a".repeat(65),
        &"z".repeat(64),
    ] {
        assert!(
            matches!(
                Fingerprint::parse(bad),
                Err(Error::InvalidIdentifier {
                    kind: "workspace fingerprint",
                    ..
                })
            ),
            "{bad:?} should be rejected"
        );
    }
}
