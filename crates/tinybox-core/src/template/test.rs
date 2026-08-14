//! Tests for the template index.

use super::{MemoryTemplates, Templates};
use crate::error::{Error, Result};
use crate::identity::{SnapshotId, TemplateName};

fn name(value: &str) -> Result<TemplateName> {
    TemplateName::new(value)
}

fn snapshot(value: &str) -> Result<SnapshotId> {
    SnapshotId::new(value)
}

#[test]
fn a_saved_template_can_be_read_back() -> Result<()> {
    let templates = MemoryTemplates::new();

    templates.save(&name("rust-ci")?, &snapshot("sha-9f2c0e1b7a4d")?)?;

    assert_eq!(
        templates.get(&name("rust-ci")?)?.as_str(),
        "sha-9f2c0e1b7a4d"
    );
    Ok(())
}

#[test]
fn saving_the_same_name_again_updates_it() -> Result<()> {
    let templates = MemoryTemplates::new();
    templates.save(&name("rust-ci")?, &snapshot("sha-aaaaaaaaaaaa")?)?;

    // Rebuilding a template and re-saving it under the same name is the normal
    // way to update one, so this must replace rather than refuse.
    templates.save(&name("rust-ci")?, &snapshot("sha-bbbbbbbbbbbb")?)?;

    assert_eq!(
        templates.get(&name("rust-ci")?)?.as_str(),
        "sha-bbbbbbbbbbbb"
    );
    assert_eq!(templates.list()?.len(), 1);
    Ok(())
}

#[test]
fn an_unsaved_name_is_reported_rather_than_invented() -> Result<()> {
    let templates = MemoryTemplates::new();
    let missing = name("absent")?;
    let expected = Some(Error::UnknownTemplate {
        name: "absent".to_owned(),
    });

    assert_eq!(templates.get(&missing).err(), expected);
    assert_eq!(templates.remove(&missing).err(), expected);
    Ok(())
}

#[test]
fn listing_is_ordered_by_name() -> Result<()> {
    let templates = MemoryTemplates::new();
    for value in ["zeta", "alpha", "mid"] {
        templates.save(&name(value)?, &snapshot("sha-000000000000")?)?;
    }

    let names = templates
        .list()?
        .into_iter()
        .map(|(name, _)| name.into_string())
        .collect::<Vec<_>>();

    assert_eq!(names, ["alpha", "mid", "zeta"]);
    Ok(())
}

#[test]
fn removing_a_template_retires_the_name_not_the_snapshot() -> Result<()> {
    let templates = MemoryTemplates::new();
    let target = snapshot("sha-9f2c0e1b7a4d")?;
    templates.save(&name("one")?, &target)?;
    templates.save(&name("two")?, &target)?;

    templates.remove(&name("one")?)?;

    // Two names can point at one snapshot, so retiring a name must leave the
    // other pointing somewhere real.
    assert!(templates.get(&name("one")?).is_err());
    assert_eq!(templates.get(&name("two")?)?, target);
    Ok(())
}

#[test]
fn a_template_name_follows_the_usual_identifier_rule() {
    // It ends up in a store file and on a command line like every other name.
    for bad in ["", "../escape", "has space", "a/b"] {
        assert!(
            TemplateName::new(bad).is_err(),
            "{bad:?} should be rejected"
        );
    }
    assert!(TemplateName::new("rust-ci.2").is_ok());
}

#[test]
fn an_empty_index_lists_nothing() -> Result<()> {
    assert!(MemoryTemplates::default().list()?.is_empty());
    Ok(())
}

#[test]
fn it_is_usable_behind_a_trait_object() -> Result<()> {
    let templates: Box<dyn Templates> = Box::new(MemoryTemplates::new());

    templates.save(&name("t")?, &snapshot("sha-000000000000")?)?;
    assert_eq!(templates.list()?.len(), 1);
    Ok(())
}
