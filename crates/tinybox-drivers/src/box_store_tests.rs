use super::*;
use crate::faulty::{Faults, Faulty};
use serde_json::json;
use tinybox_core::store::insert_new;
use tinybox_core::{BoxSpec, HostRef, Placement, SandboxRef, WorkspaceSource};
use tinystoragedrivers_api::DocumentStore;
use tinystoragedrivers_testkit::memory_storage;
use tinystoragedrivers_types::{Precondition, Scope, StorageError};

fn documents() -> Arc<dyn DocumentStore> {
    memory_storage(&Scope::new("tinybox-tests").expect("scope"))
        .documents()
        .clone()
}

fn test_store(docs: Arc<dyn DocumentStore>) -> Result<DocumentBoxStore> {
    let bridge = Blocking::new().expect("bridge");
    let ensure_docs = Arc::clone(&docs);
    bridge
        .run(async move {
            for spec in tinybox_bus::storage::collections() {
                ensure_docs.ensure_collection(&spec).await?;
            }
            Ok::<_, StorageError>(())
        })
        .expect("bridge")
        .expect("collections");
    let boxes = Repo::new(&docs, BOX_COLLECTION)
        .map_err(|error| store_error("test", &error))?
        .with_options(WriteOptions::new().schema(BODY_VERSION));
    drop(docs);
    Ok(DocumentBoxStore { boxes, bridge })
}

fn spec() -> Result<BoxSpec> {
    Ok(BoxSpec::new(
        Placement::new(HostRef::new("local")?, SandboxRef::new("passthrough")?),
        WorkspaceSource::LocalDir("/srv/work".into()),
    )
    .with_env("KEY", "value"))
}

fn info(id: &str) -> Result<BoxInfo> {
    Ok(BoxInfo::new(BoxId::new(id)?, BoxState::Ready, spec()?))
}

#[test]
fn an_inserted_box_round_trips() -> Result<()> {
    let store = test_store(documents())?;
    let original = info("build-1")?;
    store.insert(&original)?;
    assert_eq!(store.get(&original.id)?, original);
    assert_eq!(store.list()?, vec![original]);
    Ok(())
}

#[test]
fn a_second_insert_of_one_id_is_a_duplicate() -> Result<()> {
    let store = test_store(documents())?;
    store.insert(&info("a")?)?;
    assert!(matches!(
        store.insert(&info("a")?),
        Err(Error::DuplicateBox { id }) if id == "a"
    ));
    Ok(())
}

#[test]
fn an_unknown_box_is_reported_by_every_operation() -> Result<()> {
    let store = test_store(documents())?;
    let id = BoxId::new("ghost")?;
    assert!(matches!(store.get(&id), Err(Error::UnknownBox { .. })));
    assert!(matches!(
        store.set_state(&id, BoxState::Stopped),
        Err(Error::UnknownBox { .. })
    ));
    assert!(matches!(store.remove(&id), Err(Error::UnknownBox { .. })));
    Ok(())
}

#[test]
fn set_state_and_remove_change_the_record() -> Result<()> {
    let store = test_store(documents())?;
    let record = info("a")?;
    store.insert(&record)?;
    store.set_state(&record.id, BoxState::Stopped)?;
    assert_eq!(store.get(&record.id)?.state, BoxState::Stopped);
    store.remove(&record.id)?;
    assert_eq!(store.list()?.len(), 0);
    Ok(())
}

#[test]
fn list_is_ordered_by_identifier() -> Result<()> {
    let store = test_store(documents())?;
    for id in ["c", "a", "b"] {
        store.insert(&info(id)?)?;
    }
    let ids: Vec<String> = store
        .list()?
        .into_iter()
        .map(|record| record.id.into_string())
        .collect();
    assert_eq!(ids, ["a", "b", "c"]);
    Ok(())
}

#[test]
fn allocation_takes_the_lowest_free_name() -> Result<()> {
    let store = test_store(documents())?;
    let first = insert_new(&store, BoxState::Ready, &spec()?, std::time::UNIX_EPOCH)?;
    let second = insert_new(&store, BoxState::Ready, &spec()?, std::time::UNIX_EPOCH)?;
    assert_eq!(first.id.as_str(), "box-0");
    assert_eq!(second.id.as_str(), "box-1");
    Ok(())
}

#[test]
fn concurrent_allocation_never_loses_or_repeats_a_box() -> Result<()> {
    let store = Arc::new(test_store(documents())?);
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let store = Arc::clone(&store);
            std::thread::spawn(move || {
                insert_new(
                    store.as_ref(),
                    BoxState::Ready,
                    &spec().expect("spec"),
                    std::time::UNIX_EPOCH,
                )
                .map(|created| created.id.into_string())
            })
        })
        .collect();
    let mut ids = std::collections::BTreeSet::new();
    for handle in handles {
        let id = handle.join().expect("thread")?;
        assert!(ids.insert(id), "an identifier was handed out twice");
    }
    assert_eq!(store.list()?.len(), 8);
    Ok(())
}

#[test]
fn concurrent_state_changes_on_different_boxes_all_land() -> Result<()> {
    let store = Arc::new(test_store(documents())?);
    for id in ["a", "b", "c", "d"] {
        store.insert(&info(id)?)?;
    }
    let handles: Vec<_> = ["a", "b", "c", "d"]
        .into_iter()
        .map(|id| {
            let store = Arc::clone(&store);
            std::thread::spawn(move || {
                store.set_state(&BoxId::new(id).expect("id"), BoxState::Stopped)
            })
        })
        .collect();
    for handle in handles {
        handle.join().expect("thread")?;
    }
    assert!(store.list()?.iter().all(|r| r.state == BoxState::Stopped));
    Ok(())
}

#[test]
fn a_document_that_does_not_decode_is_a_store_error() -> Result<()> {
    let docs = documents();
    let store = test_store(Arc::clone(&docs))?;
    let bridge = Blocking::new().expect("bridge");
    let writer = Arc::clone(&docs);
    bridge
        .run(async move {
            writer
                .put(
                    BOX_COLLECTION,
                    "bad",
                    json!({"nope": 1}),
                    Precondition::None,
                )
                .await
        })
        .expect("bridge")
        .expect("put");
    assert!(matches!(
        store.get(&BoxId::new("bad")?),
        Err(Error::Store {
            operation: "decode",
            ..
        })
    ));
    Ok(())
}

#[test]
fn synchronous_store_calls_fail_from_a_current_thread_runtime() -> Result<()> {
    let store = test_store(documents())?;
    let runtime = tokio_rt();
    let refused = runtime.block_on(async { store.insert(&info("a")?) });
    assert!(matches!(
        refused,
        Err(Error::Store {
            operation: "insert",
            ..
        })
    ));
    assert_eq!(store.list()?, Vec::<BoxInfo>::new());
    Ok(())
}

fn tokio_rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime")
}

#[test]
fn backend_failures_surface_as_store_errors_per_operation() -> Result<()> {
    let seeded = documents();
    let record = info("a")?;
    test_store(Arc::clone(&seeded))?.insert(&record)?;
    let store_with =
        |faults: Faults| test_store(Faulty::new(Arc::clone(&seeded), faults)).expect("open");

    let reading = store_with(Faults {
        get: true,
        ..Faults::default()
    });
    assert!(matches!(
        reading.get(&record.id),
        Err(Error::Store {
            operation: "read",
            ..
        })
    ));
    let reading_update = store_with(Faults {
        get: true,
        ..Faults::default()
    });
    assert!(matches!(
        reading_update.set_state(&record.id, BoxState::Stopped),
        Err(Error::Store {
            operation: "update",
            ..
        })
    ));

    let listing = store_with(Faults {
        query: true,
        ..Faults::default()
    });
    assert!(matches!(
        listing.list(),
        Err(Error::Store {
            operation: "list",
            ..
        })
    ));

    let writing = store_with(Faults {
        put: true,
        ..Faults::default()
    });
    assert!(matches!(
        writing.insert(&info("b")?),
        Err(Error::Store {
            operation: "insert",
            ..
        })
    ));
    let writing_update = store_with(Faults {
        put: true,
        ..Faults::default()
    });
    assert!(matches!(
        writing_update.set_state(&record.id, BoxState::Stopped),
        Err(Error::Store {
            operation: "update",
            ..
        })
    ));

    let removing = store_with(Faults {
        delete: true,
        ..Faults::default()
    });
    assert!(matches!(
        removing.remove(&record.id),
        Err(Error::Store {
            operation: "remove",
            ..
        })
    ));
    Ok(())
}

#[test]
fn set_state_retries_after_a_lost_race() -> Result<()> {
    let seeded = documents();
    let record = info("a")?;
    test_store(Arc::clone(&seeded))?.insert(&record)?;
    let store = test_store(Faulty::with_conflicts(Arc::clone(&seeded), 2))?;
    store.set_state(&record.id, BoxState::Stopped)?;
    assert_eq!(store.get(&record.id)?.state, BoxState::Stopped);
    Ok(())
}

#[test]
fn set_state_gives_up_when_the_record_never_settles() -> Result<()> {
    let seeded = documents();
    let record = info("a")?;
    test_store(Arc::clone(&seeded))?.insert(&record)?;
    let store = test_store(Faulty::with_conflicts(seeded, usize::MAX))?;
    assert!(matches!(
        store.set_state(&record.id, BoxState::Stopped),
        Err(Error::Store {
            operation: "update",
            ..
        })
    ));
    Ok(())
}

#[test]
fn the_debug_form_does_not_dump_the_backend() -> Result<()> {
    let store = test_store(documents())?;
    assert!(format!("{store:?}").starts_with("DocumentBoxStore"));
    Ok(())
}

#[test]
fn a_stored_box_has_the_v2_body_and_schema_version() -> Result<()> {
    let docs = documents();
    let store = test_store(Arc::clone(&docs))?;
    store.insert(&info("build-1")?)?;
    let bridge = Blocking::new().expect("bridge");
    let reader = Arc::clone(&docs);
    let stored = bridge
        .run(async move { reader.get(BOX_COLLECTION, "build-1").await })
        .expect("bridge")
        .expect("get")
        .expect("stored");
    assert_eq!(stored.meta.schema, 2);
    assert_eq!(stored.doc["state"], json!("ready"));
    assert_eq!(stored.doc["spec"]["lifecycle"]["kind"], json!("ephemeral"));
    assert!(stored.doc.get("id").is_none(), "the id is the document id");
    Ok(())
}

#[test]
fn a_box_missing_from_a_set_state_is_left_missing() -> Result<()> {
    let docs = documents();
    let store = test_store(Arc::clone(&docs))?;
    let id = BoxId::new("ghost")?;
    assert!(matches!(
        store.set_state(&id, BoxState::Stopped),
        Err(Error::UnknownBox { .. })
    ));
    assert_eq!(store.list()?.len(), 0);
    Ok(())
}

#[test]
fn more_boxes_than_one_page_all_list() -> Result<()> {
    let store = test_store(documents())?;
    for n in 0..120 {
        store.insert(&info(&format!("b{n:03}"))?)?;
    }
    assert_eq!(store.list()?.len(), 120);
    Ok(())
}
