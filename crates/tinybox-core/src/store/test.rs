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

/// A store whose first `insert` always reports the name as taken.
///
/// Stands in for another process claiming the identifier in the window between
/// allocating it and recording it.
#[derive(Debug)]
struct CollidingStore {
    inner: MemoryStore,
    collisions_left: std::sync::Mutex<usize>,
}

impl CollidingStore {
    fn new(collisions: usize) -> Self {
        Self {
            inner: MemoryStore::new(),
            collisions_left: std::sync::Mutex::new(collisions),
        }
    }

    fn take_collision(&self) -> bool {
        let mut left = self
            .collisions_left
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if *left == 0 {
            return false;
        }
        *left -= 1;
        true
    }
}

impl Store for CollidingStore {
    fn insert(&self, info: &BoxInfo) -> Result<()> {
        if self.take_collision() {
            // Record it anyway, so the next allocation genuinely picks a
            // different name rather than looping on the same one.
            self.inner.insert(info)?;
            return Err(Error::DuplicateBox {
                id: info.id.as_str().to_owned(),
            });
        }
        self.inner.insert(info)
    }

    fn get(&self, id: &BoxId) -> Result<BoxInfo> {
        self.inner.get(id)
    }

    fn list(&self) -> Result<Vec<BoxInfo>> {
        self.inner.list()
    }

    fn set_state(&self, id: &BoxId, state: BoxState) -> Result<()> {
        self.inner.set_state(id, state)
    }

    fn remove(&self, id: &BoxId) -> Result<()> {
        self.inner.remove(id)
    }
}

#[test]
fn a_new_box_is_recorded_with_its_creation_time() -> Result<()> {
    let store = MemoryStore::new();
    let now = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(120);

    let info = super::insert_new(&store, BoxState::Ready, &spec()?, now)?;

    assert_eq!(info.id.as_str(), "box-0");
    assert_eq!(info.created_at, Some(now));
    assert_eq!(store.get(&info.id)?.created_at, Some(now));
    Ok(())
}

#[test]
fn losing_a_race_for_an_identifier_retries_rather_than_failing() -> Result<()> {
    // Another process claimed `box-0` between this one allocating and
    // recording it. That is a short wait, not a reason to fail a create.
    let store = CollidingStore::new(1);

    let info = super::insert_new(
        &store,
        BoxState::Ready,
        &spec()?,
        std::time::SystemTime::UNIX_EPOCH,
    )?;

    assert_eq!(info.id.as_str(), "box-1");
    Ok(())
}

#[test]
fn repeated_collisions_give_up_rather_than_spinning() -> Result<()> {
    // A store that always collides would otherwise loop forever.
    let store = CollidingStore::new(usize::MAX);

    let outcome = super::insert_new(
        &store,
        BoxState::Ready,
        &spec()?,
        std::time::SystemTime::UNIX_EPOCH,
    );

    assert!(matches!(
        outcome,
        Err(Error::Store {
            operation: "allocate",
            ..
        })
    ));
    Ok(())
}

#[test]
fn a_failure_that_is_not_a_collision_is_not_retried() -> Result<()> {
    /// A store that refuses every write for a reason retrying cannot fix.
    #[derive(Debug)]
    struct ReadOnly;

    impl Store for ReadOnly {
        fn insert(&self, _info: &BoxInfo) -> Result<()> {
            Err(Error::Store {
                operation: "write",
                message: "read-only".to_owned(),
            })
        }
        fn get(&self, id: &BoxId) -> Result<BoxInfo> {
            Err(Error::UnknownBox {
                id: id.as_str().to_owned(),
            })
        }
        fn list(&self) -> Result<Vec<BoxInfo>> {
            Ok(Vec::new())
        }
        fn set_state(&self, _id: &BoxId, _state: BoxState) -> Result<()> {
            Ok(())
        }
        fn remove(&self, _id: &BoxId) -> Result<()> {
            Ok(())
        }
    }

    let outcome = super::insert_new(
        &ReadOnly,
        BoxState::Ready,
        &spec()?,
        std::time::SystemTime::UNIX_EPOCH,
    );

    assert!(matches!(
        outcome,
        Err(Error::Store {
            operation: "write",
            ..
        })
    ));

    // The rest of the stub behaves as the trait requires, so a future change
    // that starts calling it does not silently get nonsense.
    let id = BoxId::new("box-0")?;
    assert!(ReadOnly.list()?.is_empty());
    assert!(ReadOnly.get(&id).is_err());
    assert!(ReadOnly.set_state(&id, BoxState::Stopped).is_ok());
    assert!(ReadOnly.remove(&id).is_ok());
    Ok(())
}
