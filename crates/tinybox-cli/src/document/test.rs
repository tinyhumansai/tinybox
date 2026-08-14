//! Tests for the shared JSON document handling.
//!
//! The box store and the template index both route through here, so their
//! failure modes are tested once rather than twice.

use std::collections::BTreeMap;
use std::path::Path;

use tempfile::TempDir;
use tinybox_core::{Error, Result};

use super::{read, write};

/// The shape both real documents share.
type Records = BTreeMap<String, String>;

fn temp_dir() -> Result<TempDir> {
    TempDir::new().map_err(|error| Error::io("tempdir", &error))
}

fn records(pairs: &[(&str, &str)]) -> Records {
    pairs
        .iter()
        .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
        .collect()
}

#[test]
fn a_document_survives_a_round_trip() -> Result<()> {
    let dir = temp_dir()?;
    let path = dir.path().join("doc.json");
    let written = records(&[("a", "1"), ("b", "2")]);

    write(&path, &written)?;

    assert_eq!(read::<Records>(&path, "test document")?, written);
    Ok(())
}

#[test]
fn a_missing_file_reads_as_an_empty_document() -> Result<()> {
    let dir = temp_dir()?;

    // No initialization step: a fresh install must just work.
    let read: Records = read(&dir.path().join("absent.json"), "test document")?;

    assert!(read.is_empty());
    Ok(())
}

#[test]
fn a_corrupt_document_is_reported_and_not_treated_as_empty() -> Result<()> {
    let dir = temp_dir()?;
    let path = dir.path().join("doc.json");
    std::fs::write(&path, "{ not json").map_err(|error| Error::io("write", &error))?;

    // Treating an unreadable document as empty would silently orphan
    // everything it described.
    let outcome = read::<Records>(&path, "test document");

    assert!(matches!(
        outcome,
        Err(Error::Store {
            operation: "parse",
            ..
        })
    ));
    // The message names both the file and what it was meant to be.
    assert!(
        outcome
            .err()
            .is_some_and(|error| error.to_string().contains("test document"))
    );
    Ok(())
}

#[test]
fn a_path_that_is_a_directory_is_a_read_failure_not_a_missing_file() -> Result<()> {
    let dir = temp_dir()?;
    let path = dir.path().join("doc.json");
    std::fs::create_dir(&path).map_err(|error| Error::io("mkdir", &error))?;

    assert!(matches!(
        read::<Records>(&path, "test document"),
        Err(Error::Store {
            operation: "read",
            ..
        })
    ));
    Ok(())
}

#[test]
fn the_parent_directory_is_created_on_first_write() -> Result<()> {
    let dir = temp_dir()?;
    let path = dir.path().join("deep").join("nested").join("doc.json");

    write(&path, &records(&[("a", "1")]))?;

    assert!(path.exists());
    Ok(())
}

#[test]
fn a_parent_that_cannot_be_created_is_reported() -> Result<()> {
    let dir = temp_dir()?;
    let blocker = dir.path().join("blocker");
    std::fs::write(&blocker, "not a directory").map_err(|error| Error::io("write", &error))?;

    // The parent exists but is a file, so nothing under it can be made.
    let outcome = write(&blocker.join("doc.json"), &records(&[("a", "1")]));

    assert!(matches!(outcome, Err(Error::Store { .. })));
    Ok(())
}

#[test]
fn a_path_with_no_parent_is_reported() {
    // The filesystem root has nowhere to put a sibling temporary file.
    let outcome = write(Path::new("/"), &records(&[("a", "1")]));

    assert!(matches!(
        outcome,
        Err(Error::Store {
            operation: "write",
            ..
        })
    ));
}

#[test]
fn writing_leaves_no_temporary_file_behind() -> Result<()> {
    let dir = temp_dir()?;
    write(&dir.path().join("doc.json"), &records(&[("a", "1")]))?;

    let leftovers = std::fs::read_dir(dir.path())
        .map_err(|error| Error::io("readdir", &error))?
        .filter_map(std::result::Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "tmp"))
        .count();

    assert_eq!(leftovers, 0);
    Ok(())
}

#[test]
fn a_rewrite_replaces_rather_than_merges() -> Result<()> {
    let dir = temp_dir()?;
    let path = dir.path().join("doc.json");
    write(&path, &records(&[("a", "1"), ("b", "2")]))?;

    write(&path, &records(&[("c", "3")]))?;

    // Whole-document semantics: a removal has to actually remove.
    assert_eq!(
        read::<Records>(&path, "test document")?,
        records(&[("c", "3")])
    );
    Ok(())
}
