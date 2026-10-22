//! Behavior tests for document-backed `TinyBox` templates.

use super::*;
use crate::faulty::{Faults, Faulty};
use std::sync::Arc;
use tinystoragedrivers_api::{DocumentStoreExt, Storage, StorageBackend};
use tinystoragedrivers_testkit::memory_storage;
use tinystoragedrivers_types::{ErrorKind, Scope};

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

fn storage(scope: &str) -> std::result::Result<Storage, Box<dyn std::error::Error>> {
    Ok(memory_storage(&Scope::new(scope)?))
}

#[tokio::test(flavor = "multi_thread")]
async fn templates_persist_as_documents_and_round_trip() -> TestResult {
    let storage = storage("template-round-trip")?;
    let store = DocumentTemplateStore::open(storage.clone()).await?;
    let name = TemplateName::new("rust-ci")?;
    let snapshot = SnapshotId::new("snap-2a4f")?;

    store.save(&name, &snapshot)?;

    assert_eq!(store.get(&name)?, snapshot);
    assert_eq!(store.list()?, vec![(name, snapshot)]);
    let body = storage
        .documents()
        .get_as::<TemplateRecord>(TEMPLATE_COLLECTION, "rust-ci")
        .await?
        .ok_or("template document missing")?;
    assert_eq!(body.doc.snapshot.as_str(), "snap-2a4f");
    assert_eq!(body.meta.schema, BODY_VERSION);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn importing_templates_is_idempotent_but_preserves_conflicting_values() -> TestResult {
    let store = DocumentTemplateStore::open(storage("template-import")?).await?;
    let name = TemplateName::new("released")?;
    let imported = SnapshotId::new("old-snapshot")?;
    store.import_if_missing(&name, &imported)?;
    store.import_if_missing(&name, &imported)?;
    assert_eq!(store.get(&name)?, imported);

    let conflict = store.import_if_missing(&name, &SnapshotId::new("newer-snapshot")?);
    assert!(matches!(
        conflict,
        Err(Error::Store {
            operation: "import",
            ..
        })
    ));
    assert_eq!(store.get(&name)?, imported);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn template_store_debug_does_not_expose_storage_contents() -> TestResult {
    let store = DocumentTemplateStore::open(storage("template-debug")?).await?;
    let name = TemplateName::new("private-name")?;
    store.save(&name, &SnapshotId::new("private-snapshot")?)?;

    let debug = format!("{store:?}");
    assert!(debug.contains("DocumentTemplateStore"));
    assert!(!debug.contains("private-name"));
    assert!(!debug.contains("private-snapshot"));
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn resaving_replaces_a_template_and_remove_is_idempotently_reported() -> TestResult {
    let store = DocumentTemplateStore::open(storage("template-replace")?).await?;
    let name = TemplateName::new("rust-ci")?;
    store.save(&name, &SnapshotId::new("old")?)?;
    store.save(&name, &SnapshotId::new("new")?)?;
    assert_eq!(store.get(&name)?.as_str(), "new");
    store.remove(&name)?;
    assert!(matches!(
        store.get(&name),
        Err(Error::UnknownTemplate { name }) if name == "rust-ci"
    ));
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn template_names_are_isolated_by_the_supplied_scope() -> TestResult {
    let backend = tinystoragedrivers_testkit::MemoryBackend::new();
    let left_storage = backend.for_scope(&Scope::new("template-left")?)?;
    let right_storage = backend.for_scope(&Scope::new("template-right")?)?;
    let left = DocumentTemplateStore::open(left_storage).await?;
    let right = DocumentTemplateStore::open(right_storage).await?;
    let name = TemplateName::new("release")?;
    left.save(&name, &SnapshotId::new("left")?)?;
    assert!(matches!(
        right.get(&name),
        Err(Error::UnknownTemplate { .. })
    ));
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn listing_walks_all_pages_and_missing_removal_is_reported() -> TestResult {
    let storage = storage("template-pages")?;
    let store = DocumentTemplateStore::open(storage.clone()).await?;
    for index in 0..300 {
        let name = TemplateName::new(format!("template-{index:03}"))?;
        store.save(&name, &SnapshotId::new(format!("snapshot-{index}"))?)?;
    }

    let listed = store.list()?;
    assert_eq!(listed.len(), 300);
    assert_eq!(listed[0].0.as_str(), "template-000");
    assert_eq!(listed[299].0.as_str(), "template-299");
    assert!(matches!(
        store.remove(&TemplateName::new("missing")?),
        Err(Error::UnknownTemplate { name }) if name == "missing"
    ));
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn malformed_template_rows_fail_reads_and_lists_without_hiding_the_error() -> TestResult {
    let storage = storage("template-malformed")?;
    let store = DocumentTemplateStore::open(storage.clone()).await?;
    storage
        .documents()
        .put_with(
            TEMPLATE_COLLECTION,
            "broken",
            serde_json::json!({"snapshot": 7}),
            tinystoragedrivers_types::Precondition::Absent,
            tinystoragedrivers_types::WriteOptions::new().schema(BODY_VERSION),
        )
        .await?;

    assert!(matches!(
        store.get(&TemplateName::new("broken")?),
        Err(Error::Store {
            operation: "read",
            ..
        })
    ));
    assert!(matches!(
        store.list(),
        Err(Error::Store {
            operation: "list",
            ..
        })
    ));
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn template_port_failures_keep_the_operation_context() -> TestResult {
    let base = storage("template-operation-failures")?;
    let faulty = Faulty::new(Arc::clone(base.documents()), Faults::default());
    let wrapped = Storage::new(
        faulty.clone(),
        Arc::clone(base.streams()),
        Arc::clone(base.kv()),
        Arc::clone(base.blobs()),
        Arc::clone(base.queues()),
        Arc::clone(base.secrets()),
    );
    let store = DocumentTemplateStore::open(wrapped).await?;
    let name = TemplateName::new("faulted")?;
    let snapshot = SnapshotId::new("snapshot")?;

    faulty
        .failing
        .faults
        .fail_operation_nth("get", 1, ErrorKind::Backend);
    assert!(matches!(
        store.get(&name),
        Err(Error::Store {
            operation: "read",
            ..
        })
    ));

    faulty
        .failing
        .faults
        .fail_operation_nth("put", 1, ErrorKind::Backend);
    assert!(matches!(
        store.save(&name, &snapshot),
        Err(Error::Store {
            operation: "save",
            ..
        })
    ));

    faulty
        .failing
        .faults
        .fail_operation_nth("query", 1, ErrorKind::Backend);
    assert!(matches!(
        store.list(),
        Err(Error::Store {
            operation: "list",
            ..
        })
    ));

    faulty
        .failing
        .faults
        .fail_operation_nth("delete", 1, ErrorKind::Backend);
    assert!(matches!(
        store.remove(&name),
        Err(Error::Store {
            operation: "remove",
            ..
        })
    ));
    Ok(())
}
