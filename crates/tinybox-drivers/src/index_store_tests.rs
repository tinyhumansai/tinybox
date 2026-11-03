use super::*;
use crate::faulty::{Faults, Faulty};
use tinybox_core::clock::FixedClock;
use tinybox_jail::JailRegistry;
use tinystoragedrivers_api::DocumentStore;
use tinystoragedrivers_testkit::memory_storage;
use tinystoragedrivers_types::{CollectionSpec, Scope, StorageError, WriteOptions};

fn documents() -> Arc<dyn DocumentStore> {
    memory_storage(&Scope::new("tinybox-index-tests").expect("scope"))
        .documents()
        .clone()
}

fn test_store(docs: Arc<dyn DocumentStore>, registry: &str) -> io::Result<DocumentIndexStore> {
    let bridge = Blocking::new().expect("bridge");
    let ensure_docs = Arc::clone(&docs);
    bridge
        .run(async move {
            for declaration in tinybox_bus::storage::collections() {
                ensure_docs
                    .ensure_collection(&CollectionSpec::new(declaration.name))
                    .await?;
            }
            Ok::<_, StorageError>(())
        })
        .expect("bridge")
        .map_err(|error| to_io(&error))?;
    let key = Key::new(registry)
        .map_err(|error| to_io(&error))?
        .as_str()
        .to_owned();
    let index = Repo::new(&docs, JAIL_INDEX_COLLECTION)
        .map_err(|error| to_io(&error))?
        .with_options(WriteOptions::new().schema(BODY_VERSION));
    drop(docs);
    Ok(DocumentIndexStore {
        index,
        bridge,
        key,
        registry: registry.to_owned(),
    })
}

fn clock() -> Arc<FixedClock> {
    Arc::new(FixedClock::at_epoch())
}

#[test]
fn an_empty_index_loads_as_absent() {
    let store = test_store(documents(), "main").expect("store");
    assert_eq!(store.load().expect("load"), None);
}

#[test]
fn a_saved_index_loads_back_as_the_same_json() {
    let store = test_store(documents(), "main").expect("store");
    store
        .save(br#"{"records":{},"schema_version":1}"#)
        .expect("save");
    let loaded: Value =
        serde_json::from_slice(&store.load().expect("load").expect("some")).expect("json");
    assert_eq!(
        loaded,
        serde_json::json!({"records": {}, "schema_version": 1})
    );
}

#[test]
fn registries_with_different_names_do_not_share_an_index() {
    let docs = documents();
    let a = test_store(Arc::clone(&docs), "a").expect("store");
    let b = test_store(docs, "b").expect("store");
    a.save(b"{}").expect("save");
    assert_eq!(b.load().expect("load"), None);
}

#[test]
fn saving_something_that_is_not_json_is_invalid_data() {
    let store = test_store(documents(), "main").expect("store");
    let error = store.save(b"not json").expect_err("rejected");
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
}

#[test]
fn a_registry_keeps_its_jails_across_reopen_without_an_index_file() {
    let base = tempfile::tempdir().expect("dir");
    let docs = documents();
    let store = Arc::new(test_store(docs, "main").expect("store"));

    let registry =
        JailRegistry::open_with_store(base.path(), clock(), store.clone()).expect("open");
    let created = registry.create("alpha").expect("create");
    registry.rename(&created.id, "beta").expect("rename");
    registry
        .set_notes(&created.id, Some("n".into()))
        .expect("notes");
    drop(registry);

    // The metadata lives in the document, not in `index.json`.
    assert!(!base.path().join("index.json").exists());

    let reopened = JailRegistry::open_with_store(base.path(), clock(), store).expect("reopen");
    let record = reopened.get(&created.id).expect("record");
    assert_eq!(record.label, "beta");
    assert_eq!(record.notes.as_deref(), Some("n"));

    reopened.delete(&created.id).expect("delete");
    assert!(reopened.list().is_empty());
}

#[test]
fn backend_failures_surface_as_io_errors() {
    assert!(test_store(documents(), "").is_err());

    let reading = test_store(
        Faulty::new(
            documents(),
            Faults {
                get: true,
                ..Faults::default()
            },
        ),
        "main",
    )
    .expect("store");
    assert_eq!(
        reading.load().expect_err("load fails").kind(),
        io::ErrorKind::Other
    );

    let writing = test_store(
        Faulty::new(
            documents(),
            Faults {
                put: true,
                ..Faults::default()
            },
        ),
        "main",
    )
    .expect("store");
    assert_eq!(
        writing.save(b"{}").expect_err("save fails").kind(),
        io::ErrorKind::Other
    );
}

#[test]
fn storage_error_kinds_map_to_io_kinds() {
    assert_eq!(
        to_io(&StorageError::not_found("x")).kind(),
        io::ErrorKind::NotFound
    );
    assert_eq!(
        to_io(&StorageError::serialization("x")).kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!(
        to_io(&StorageError::backend("x")).kind(),
        io::ErrorKind::Other
    );
}

#[test]
fn the_debug_form_names_the_registry() {
    let store = test_store(documents(), "main").expect("store");
    assert!(format!("{store:?}").contains("main"));
}

#[test]
fn a_saved_index_is_stored_with_millisecond_times_and_the_v2_schema() {
    let docs = documents();
    let store = test_store(Arc::clone(&docs), "main").expect("store");
    store
        .save(
            br#"{"records":{"j1":{"id":"j1","created_at_unix":2,"updated_at_unix":3}},"schema_version":1}"#,
        )
        .expect("save");
    let bridge = Blocking::new().expect("bridge");
    let reader = Arc::clone(&docs);
    let stored = bridge
        .run(async move { reader.get(JAIL_INDEX_COLLECTION, "main").await })
        .expect("bridge")
        .expect("get")
        .expect("stored");
    assert_eq!(stored.meta.schema, 2);
    assert_eq!(
        stored.doc,
        serde_json::json!({"records": {"j1": {"id": "j1", "created_ms": 2000, "updated_ms": 3000}}})
    );
}
