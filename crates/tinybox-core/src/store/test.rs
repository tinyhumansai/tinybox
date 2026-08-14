//! Tests for the box store and its in-memory implementation.

use super::{MemoryStore, Store};
use crate::error::{Error, Result};
use crate::identity::{BoxId, HostRef, SandboxRef};
use crate::runtime::{BoxInfo, BoxState};
use crate::spec::{BoxSpec, Placement, WorkspaceSource};

fn spec() -> Result<BoxSpec> {
    Ok(BoxSpec::new(
        Placement::new(HostRef::new("local")?, SandboxRef::new("passthrough")?),
        WorkspaceSource::LocalDir("/srv/work".into()),
    ))
}

fn info(id: &str) -> Result<BoxInfo> {
    Ok(BoxInfo::new(BoxId::new(id)?, BoxState::Ready, spec()?))
}

#[test]
fn a_record_survives_a_round_trip() -> Result<()> {
    let store = MemoryStore::new();
    let recorded = info("box-0")?;

    store.insert(&recorded)?;

    assert_eq!(store.get(&recorded.id)?, recorded);
    assert_eq!(store.list()?, vec![recorded]);
    Ok(())
}

#[test]
fn inserting_the_same_id_twice_is_refused() -> Result<()> {
    let store = MemoryStore::new();
    store.insert(&info("box-0")?)?;

    assert_eq!(
        store.insert(&info("box-0")?).err(),
        Some(Error::DuplicateBox {
            id: "box-0".to_owned()
        })
    );
    // The original is untouched.
    assert_eq!(store.list()?.len(), 1);
    Ok(())
}

#[test]
fn an_absent_box_is_reported_rather_than_invented() -> Result<()> {
    let store = MemoryStore::new();
    let missing = BoxId::new("absent")?;
    let expected = Some(Error::UnknownBox {
        id: "absent".to_owned(),
    });

    assert_eq!(store.get(&missing).err(), expected);
    assert_eq!(store.remove(&missing).err(), expected);
    assert_eq!(store.set_state(&missing, BoxState::Stopped).err(), expected);
    Ok(())
}

#[test]
fn state_changes_are_recorded() -> Result<()> {
    let store = MemoryStore::new();
    let recorded = info("box-0")?;
    store.insert(&recorded)?;

    store.set_state(&recorded.id, BoxState::Stopped)?;

    assert_eq!(store.get(&recorded.id)?.state, BoxState::Stopped);
    Ok(())
}

#[test]
fn removing_a_box_forgets_it() -> Result<()> {
    let store = MemoryStore::new();
    let recorded = info("box-0")?;
    store.insert(&recorded)?;

    store.remove(&recorded.id)?;

    assert!(store.list()?.is_empty());
    assert!(store.get(&recorded.id).is_err());
    Ok(())
}

#[test]
fn listing_is_ordered_by_identifier() -> Result<()> {
    let store = MemoryStore::new();
    for id in ["box-2", "box-0", "box-1"] {
        store.insert(&info(id)?)?;
    }

    let ids = store
        .list()?
        .into_iter()
        .map(|info| info.id.into_string())
        .collect::<Vec<_>>();

    assert_eq!(ids, ["box-0", "box-1", "box-2"]);
    Ok(())
}

#[test]
fn allocation_takes_the_lowest_free_identifier() -> Result<()> {
    let store = MemoryStore::new();

    assert_eq!(store.allocate_id()?.as_str(), "box-0");

    store.insert(&info("box-0")?)?;
    assert_eq!(store.allocate_id()?.as_str(), "box-1");

    store.insert(&info("box-1")?)?;
    assert_eq!(store.allocate_id()?.as_str(), "box-2");
    Ok(())
}

#[test]
fn allocation_reuses_a_gap_left_by_a_removal() -> Result<()> {
    let store = MemoryStore::new();
    store.insert(&info("box-0")?)?;
    store.insert(&info("box-1")?)?;

    store.remove(&BoxId::new("box-0")?)?;

    // Reproducible rather than monotonic: the lowest free name is taken, which
    // is what keeps identifiers short and the tests deterministic.
    assert_eq!(store.allocate_id()?.as_str(), "box-0");
    Ok(())
}

#[test]
fn allocation_steps_past_identifiers_that_are_not_generated_names() -> Result<()> {
    let store = MemoryStore::new();
    store.insert(&info("hand-named")?)?;

    assert_eq!(store.allocate_id()?.as_str(), "box-0");
    Ok(())
}

#[test]
fn a_default_store_is_empty() -> Result<()> {
    assert!(MemoryStore::default().list()?.is_empty());
    Ok(())
}
