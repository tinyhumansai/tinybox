//! Tests for the file-backed template index.

use std::path::Path;

use tempfile::TempDir;
use tinybox_core::{Error, Result, SnapshotId, TemplateName, Templates};

use super::FileTemplates;

fn temp_dir() -> Result<TempDir> {
    TempDir::new().map_err(|error| Error::io("tempdir", &error))
}

/// An index in a throwaway directory, and the directory keeping it alive.
fn templates() -> Result<(FileTemplates, TempDir)> {
    let dir = temp_dir()?;
    Ok((FileTemplates::new(dir.path().join("templates.json")), dir))
}

fn name(value: &str) -> Result<TemplateName> {
    TemplateName::new(value)
}

fn snapshot(value: &str) -> Result<SnapshotId> {
    SnapshotId::new(value)
}

#[test]
fn a_missing_file_reads_as_an_empty_index() -> Result<()> {
    let (templates, _dir) = templates()?;

    assert!(!templates.path().exists());
    assert!(templates.list()?.is_empty());
    Ok(())
}

#[test]
fn a_template_survives_being_written_and_read_back() -> Result<()> {
    let (templates, _dir) = templates()?;
    templates.save(&name("rust-ci")?, &snapshot("sha-9f2c0e1b7a4d")?)?;

    // A second handle on the same path is what a later invocation sees.
    let reopened = FileTemplates::new(templates.path());

    assert_eq!(
        reopened.get(&name("rust-ci")?)?.as_str(),
        "sha-9f2c0e1b7a4d"
    );
    assert_eq!(reopened.list()?.len(), 1);
    Ok(())
}

#[test]
fn saving_over_a_name_updates_it_on_disk() -> Result<()> {
    let (templates, _dir) = templates()?;
    templates.save(&name("ci")?, &snapshot("sha-aaaaaaaaaaaa")?)?;

    templates.save(&name("ci")?, &snapshot("sha-bbbbbbbbbbbb")?)?;

    assert_eq!(
        FileTemplates::new(templates.path())
            .get(&name("ci")?)?
            .as_str(),
        "sha-bbbbbbbbbbbb"
    );
    Ok(())
}

#[test]
fn removals_persist() -> Result<()> {
    let (templates, _dir) = templates()?;
    templates.save(&name("ci")?, &snapshot("sha-9f2c0e1b7a4d")?)?;

    templates.remove(&name("ci")?)?;

    assert!(FileTemplates::new(templates.path()).list()?.is_empty());
    Ok(())
}

#[test]
fn an_unsaved_name_is_reported() -> Result<()> {
    let (templates, _dir) = templates()?;
    let missing = name("absent")?;
    let expected = Some(Error::UnknownTemplate {
        name: "absent".to_owned(),
    });

    assert_eq!(templates.get(&missing).err(), expected);
    assert_eq!(templates.remove(&missing).err(), expected);
    Ok(())
}

#[test]
fn a_corrupt_index_is_reported_and_not_silently_reset() -> Result<()> {
    let (templates, _dir) = templates()?;
    std::fs::write(templates.path(), "{ not json").map_err(|error| Error::io("write", &error))?;

    // Treating an unreadable index as empty would quietly lose every name.
    assert!(matches!(
        templates.list(),
        Err(Error::Store {
            operation: "parse",
            ..
        })
    ));
    Ok(())
}

#[test]
fn a_name_rejected_by_the_constructor_cannot_be_smuggled_in() -> Result<()> {
    let (templates, _dir) = templates()?;
    std::fs::write(templates.path(), r#"{"../escape": "sha-9f2c0e1b7a4d"}"#)
        .map_err(|error| Error::io("write", &error))?;

    assert!(templates.list().is_err());
    Ok(())
}

#[test]
fn the_index_sits_beside_the_box_store() {
    let templates = FileTemplates::beside(Path::new("/srv/state/boxes.json"));

    // Pointing `--store` elsewhere has to move both, or one directory's boxes
    // end up mixed with another directory's names.
    assert_eq!(templates.path(), Path::new("/srv/state/templates.json"));
}

#[test]
fn writing_leaves_no_temporary_file_behind() -> Result<()> {
    let (templates, dir) = templates()?;
    templates.save(&name("ci")?, &snapshot("sha-9f2c0e1b7a4d")?)?;

    let leftovers = std::fs::read_dir(dir.path())
        .map_err(|error| Error::io("readdir", &error))?
        .filter_map(std::result::Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "tmp"))
        .count();

    assert_eq!(leftovers, 0);
    Ok(())
}
