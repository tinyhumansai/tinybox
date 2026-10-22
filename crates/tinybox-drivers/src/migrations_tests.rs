use super::*;
use crate::faulty::{Faults, Faulty};
use serde_json::json;
use std::sync::Arc;
use tinybox_core::{
    BoxId, BoxInfo, BoxSpec, BoxState, HostRef, Placement, SandboxRef, Store, WorkspaceSource,
};
use tinybox_jail::IndexStore;

use tinystoragedrivers_document::memory::MemoryConnection;
use tinystoragedrivers_testkit::memory_storage;
use tinystoragedrivers_types::{Precondition, Scope};

use crate::{DocumentBoxStore, DocumentIndexStore};

use tinybox_bus::storage::BOX_COLLECTION;

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

fn storage(scope: &str) -> std::result::Result<Storage, Box<dyn std::error::Error>> {
    let scope = Scope::new(scope)?;
    let other_ports = memory_storage(&scope);
    let documents_and_streams = MemoryConnection::with_clock(Arc::new(|| 0)).for_scope(scope);
    Ok(Storage::new(
        documents_and_streams.documents(),
        documents_and_streams.streams(),
        Arc::clone(other_ports.kv()),
        Arc::clone(other_ports.blobs()),
        Arc::clone(other_ports.queues()),
        Arc::clone(other_ports.secrets()),
    ))
}

fn old_box(id: &str) -> Value {
    json!({
        "id": id,
        "state": "Paused",
        "spec": {
            "runner": {"host": "local", "sandbox": "passthrough"},
            "workspace": {"host": "local", "sandbox": "passthrough"},
            "source": {"GitRepo": {"url": "https://x.test/r", "rev": "main"}},
            "resources": {"cpu_millis": 1, "memory_bytes": 2, "pids_max": 3, "disk_bytes": 4},
            "lifecycle": {"Persistent": {}},
            "network": "Open",
            "env": {}
        },
        "created_at": {"secs_since_epoch": 2, "nanos_since_epoch": 3_000_000}
    })
}

async fn seed_legacy(
    storage: &Storage,
    id: &str,
    body: Value,
    expires_ms: Option<i64>,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let documents = storage.documents();
    documents
        .ensure_collection(&CollectionSpec::new(V1_BOX_COLLECTION))
        .await?;
    let options = expires_ms.map_or_else(WriteOptions::new, |expiry| {
        WriteOptions::new().expires_ms(expiry)
    });
    documents
        .put_with(V1_BOX_COLLECTION, id, body, Precondition::Absent, options)
        .await?;
    Ok(())
}

fn with_document_fault(storage: &Storage, faults: Faults) -> Storage {
    Storage::new(
        Faulty::new(Arc::clone(storage.documents()), faults),
        Arc::clone(storage.streams()),
        Arc::clone(storage.kv()),
        Arc::clone(storage.blobs()),
        Arc::clone(storage.queues()),
        Arc::clone(storage.secrets()),
    )
}

#[tokio::test]
async fn migration_preserves_expiry_and_verifies_before_removing_source() -> TestResult {
    let storage = storage("tinybox-migrate-expiry")?;
    seed_legacy(&storage, "b1", old_box("b1"), Some(789)).await?;

    prepare(&storage).await?;

    let target = storage
        .documents()
        .get(BOX_COLLECTION, "b1")
        .await?
        .ok_or_else(|| std::io::Error::other("target exists"))?;
    assert_eq!(target.meta.schema, BODY_VERSION);
    assert_eq!(target.meta.expires_ms, Some(789));
    assert_eq!(target.doc["created_ms"], 2003);
    assert!(
        storage
            .documents()
            .get(V1_BOX_COLLECTION, "b1")
            .await?
            .is_none()
    );
    Ok(())
}

#[tokio::test]
async fn an_existing_destination_with_a_different_expiry_preserves_legacy_source() -> TestResult {
    let storage = storage("tinybox-migrate-expiry-conflict")?;
    let old = old_box("b1");
    seed_legacy(&storage, "b1", old.clone(), Some(789)).await?;
    let target = box_v1::to_body(old).map_err(std::io::Error::other)?;
    storage
        .documents()
        .ensure_collection(&CollectionSpec::new(BOX_COLLECTION))
        .await?;
    storage
        .documents()
        .put_with(
            BOX_COLLECTION,
            "b1",
            target,
            Precondition::Absent,
            WriteOptions::new().schema(BODY_VERSION).expires_ms(456),
        )
        .await?;

    let error = prepare(&storage)
        .await
        .err()
        .ok_or_else(|| std::io::Error::other("expiry mismatch"))?;

    assert_eq!(error.kind(), ErrorKind::Conflict);
    assert!(
        storage
            .documents()
            .get(V1_BOX_COLLECTION, "b1")
            .await?
            .is_some()
    );
    Ok(())
}

#[tokio::test]
async fn a_future_receipt_fails_closed_before_migrating_any_source() -> TestResult {
    let storage = storage("tinybox-migrate-future-receipt")?;
    seed_legacy(&storage, "b1", old_box("b1"), None).await?;
    storage
        .documents()
        .ensure_collection(&CollectionSpec::new(MIGRATIONS_COLLECTION))
        .await?;
    storage
        .documents()
        .put_with(
            MIGRATIONS_COLLECTION,
            BOXES_STEP,
            json!({"step": BOXES_STEP, "version": 9, "complete": true}),
            Precondition::Absent,
            WriteOptions::new().schema(BODY_VERSION),
        )
        .await?;

    let error = prepare(&storage)
        .await
        .err()
        .ok_or_else(|| std::io::Error::other("future receipt refused"))?;

    assert_eq!(error.kind(), ErrorKind::Conflict);
    assert!(
        storage
            .documents()
            .get(V1_BOX_COLLECTION, "b1")
            .await?
            .is_some()
    );
    assert!(
        storage
            .documents()
            .get(BOX_COLLECTION, "b1")
            .await?
            .is_none()
    );
    Ok(())
}

#[tokio::test]
async fn malformed_or_unrepresentable_legacy_rows_are_not_deleted() -> TestResult {
    let storage = storage("tinybox-migrate-unknown-field")?;
    let mut old = old_box("b1");
    old["future_field"] = json!("preserve me");
    seed_legacy(&storage, "b1", old.clone(), None).await?;

    assert!(prepare(&storage).await.is_err());
    assert_eq!(
        storage
            .documents()
            .get(V1_BOX_COLLECTION, "b1")
            .await?
            .ok_or_else(|| std::io::Error::other("source preserved"))?
            .doc,
        old
    );
    assert!(
        storage
            .documents()
            .get(BOX_COLLECTION, "b1")
            .await?
            .is_none()
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn released_v1_driver_collection_rows_open_and_read_through_current_stores() -> TestResult {
    let storage = storage("tinybox-released-driver-rows")?;
    let fixtures: Vec<Value> = serde_json::from_str(include_str!(
        "../../tinybox-bin/tests/fixtures/legacy-v0.1.40/collections/documents.json"
    ))?;
    let documents = storage.documents();
    for row in &fixtures {
        let collection = row["collection"]
            .as_str()
            .ok_or_else(|| std::io::Error::other("fixture collection"))?;
        let id = row["id"]
            .as_str()
            .ok_or_else(|| std::io::Error::other("fixture id"))?;
        let schema = row["schema"]
            .as_u64()
            .and_then(|schema| u32::try_from(schema).ok())
            .ok_or_else(|| std::io::Error::other("fixture schema"))?;
        let expires_ms = row["expires_ms"].as_i64();
        let mut options = WriteOptions::new().schema(schema);
        if let Some(expires_ms) = expires_ms {
            options = options.expires_ms(expires_ms);
        }
        documents
            .ensure_collection(&CollectionSpec::new(collection))
            .await?;
        documents
            .put_with(
                collection,
                id,
                row["body"].clone(),
                Precondition::Absent,
                options,
            )
            .await?;
    }

    let boxes = DocumentBoxStore::open(storage.clone()).await?;
    let box_info = boxes.get(&BoxId::new("fixture-box")?)?;
    let expected = BoxInfo::new(
        BoxId::new("fixture-box")?,
        BoxState::Ready,
        BoxSpec::new(
            Placement::new(HostRef::new("local")?, SandboxRef::new("passthrough")?),
            WorkspaceSource::LocalDir("/srv/fixture-workspace".into()),
        )
        .with_env("FIXTURE", "public-document-writer"),
    );
    assert_eq!(box_info, expected);

    let index = DocumentIndexStore::open(storage, "fixture-registry").await?;
    let index: Value = serde_json::from_slice(
        &index
            .load()?
            .ok_or_else(|| std::io::Error::other("released index row missing"))?,
    )?;
    assert_eq!(
        index,
        json!({
            "records": {
                "jail-fixture": {
                    "id": "jail-fixture",
                    "label": "fixture",
                    "created_at_unix": 1_700_000_000_u64,
                    "updated_at_unix": 1_700_000_001_u64,
                }
            },
            "schema_version": 1
        })
    );
    Ok(())
}

#[tokio::test]
async fn a_delete_failure_preserves_source_and_retry_finishes_safely() -> TestResult {
    let storage = storage("tinybox-migrate-delete-failure")?;
    seed_legacy(&storage, "b1", old_box("b1"), None).await?;
    let faulty = with_document_fault(
        &storage,
        Faults {
            delete: true,
            ..Faults::default()
        },
    );

    assert!(prepare(&faulty).await.is_err());
    assert!(
        storage
            .documents()
            .get(V1_BOX_COLLECTION, "b1")
            .await?
            .is_some()
    );
    assert!(
        storage
            .documents()
            .get(BOX_COLLECTION, "b1")
            .await?
            .is_some()
    );

    prepare(&storage).await?;
    assert!(
        storage
            .documents()
            .get(V1_BOX_COLLECTION, "b1")
            .await?
            .is_none()
    );
    Ok(())
}

#[tokio::test]
async fn a_source_version_changed_during_copy_is_preserved() -> TestResult {
    let storage = storage("tinybox-migrate-source-race")?;
    let original = old_box("b1");
    seed_legacy(&storage, "b1", original, None).await?;
    let mut changed = old_box("b1");
    changed["created_at"]["secs_since_epoch"] = json!(7);
    let faulty = Faulty::changing_source_after_target_write(
        Arc::clone(storage.documents()),
        "b1".to_owned(),
        changed.clone(),
    );
    let raced = Storage::new(
        faulty,
        Arc::clone(storage.streams()),
        Arc::clone(storage.kv()),
        Arc::clone(storage.blobs()),
        Arc::clone(storage.queues()),
        Arc::clone(storage.secrets()),
    );

    let error = prepare(&raced)
        .await
        .err()
        .ok_or_else(|| std::io::Error::other("source version race"))?;

    assert_eq!(error.kind(), ErrorKind::Conflict);
    assert_eq!(
        storage
            .documents()
            .get(V1_BOX_COLLECTION, "b1")
            .await?
            .ok_or_else(|| std::io::Error::other("new source retained"))?
            .doc,
        changed
    );
    assert!(
        storage
            .documents()
            .get(MIGRATIONS_COLLECTION, BOXES_STEP)
            .await?
            .is_none()
    );
    Ok(())
}

#[tokio::test]
async fn a_destination_readback_failure_preserves_legacy_source() -> TestResult {
    let storage = storage("tinybox-migrate-readback-failure")?;
    seed_legacy(&storage, "b1", old_box("b1"), None).await?;
    let faulty = Faulty::failing_target_readback(Arc::clone(storage.documents()));
    let storage_with_fault = Storage::new(
        faulty,
        Arc::clone(storage.streams()),
        Arc::clone(storage.kv()),
        Arc::clone(storage.blobs()),
        Arc::clone(storage.queues()),
        Arc::clone(storage.secrets()),
    );

    assert!(prepare(&storage_with_fault).await.is_err());
    assert!(
        storage
            .documents()
            .get(V1_BOX_COLLECTION, "b1")
            .await?
            .is_some()
    );
    assert!(
        storage
            .documents()
            .get(BOX_COLLECTION, "b1")
            .await?
            .is_some()
    );
    assert!(
        storage
            .documents()
            .get(MIGRATIONS_COLLECTION, BOXES_STEP)
            .await?
            .is_none()
    );
    Ok(())
}

#[tokio::test]
async fn changed_destination_content_fails_readback_without_deleting_source() -> TestResult {
    let storage = storage("tinybox-migrate-destination-race")?;
    seed_legacy(&storage, "b1", old_box("b1"), None).await?;
    let mut replacement = box_v1::to_body(old_box("b1")).map_err(std::io::Error::other)?;
    replacement["created_ms"] = json!(9000);
    let faulty = Faulty::changing_target_after_write(
        Arc::clone(storage.documents()),
        "b1".to_owned(),
        replacement,
    );
    let raced = Storage::new(
        faulty,
        Arc::clone(storage.streams()),
        Arc::clone(storage.kv()),
        Arc::clone(storage.blobs()),
        Arc::clone(storage.queues()),
        Arc::clone(storage.secrets()),
    );

    let error = prepare(&raced)
        .await
        .err()
        .ok_or_else(|| std::io::Error::other("changed destination must fail verification"))?;

    assert_eq!(error.kind(), ErrorKind::Conflict);
    assert!(
        storage
            .documents()
            .get(V1_BOX_COLLECTION, "b1")
            .await?
            .is_some()
    );
    assert!(
        storage
            .documents()
            .get(MIGRATIONS_COLLECTION, BOXES_STEP)
            .await?
            .is_none()
    );
    Ok(())
}

#[tokio::test]
async fn a_concurrent_matching_receipt_is_accepted_idempotently() -> TestResult {
    let storage = storage("tinybox-migrate-receipt-race")?;
    seed_legacy(&storage, "b1", old_box("b1"), None).await?;
    let faulty = Faulty::racing_receipt(Arc::clone(storage.documents()));
    let raced = Storage::new(
        faulty,
        Arc::clone(storage.streams()),
        Arc::clone(storage.kv()),
        Arc::clone(storage.blobs()),
        Arc::clone(storage.queues()),
        Arc::clone(storage.secrets()),
    );

    prepare(&raced).await?;

    let receipt = storage
        .documents()
        .get(MIGRATIONS_COLLECTION, BOXES_STEP)
        .await?
        .ok_or_else(|| std::io::Error::other("concurrent receipt persisted"))?;
    assert_eq!(receipt.doc["complete"], true);
    assert!(
        storage
            .documents()
            .get(V1_BOX_COLLECTION, "b1")
            .await?
            .is_none()
    );
    Ok(())
}

#[tokio::test]
async fn a_legacy_key_and_embedded_identifier_must_match() -> TestResult {
    let storage = storage("tinybox-migrate-id-mismatch")?;
    seed_legacy(&storage, "key-id", old_box("body-id"), None).await?;

    let error = prepare(&storage)
        .await
        .err()
        .ok_or_else(|| std::io::Error::other("key mismatch"))?;

    assert_eq!(error.kind(), ErrorKind::Serialization);
    assert!(
        storage
            .documents()
            .get(V1_BOX_COLLECTION, "key-id")
            .await?
            .is_some()
    );
    Ok(())
}

#[tokio::test]
async fn an_invalid_legacy_jail_index_is_preserved_for_host_repair() -> TestResult {
    let storage = storage("tinybox-migrate-invalid-index")?;
    let invalid = json!({
        "records": {
            "jail-1": {
                "id": "jail-1",
                "label": "broken",
                "created_at_unix": -1,
                "updated_at_unix": 1
            }
        },
        "schema_version": 1
    });
    storage
        .documents()
        .ensure_collection(&CollectionSpec::new(V1_JAIL_INDEX_COLLECTION))
        .await?;
    storage
        .documents()
        .put_with(
            V1_JAIL_INDEX_COLLECTION,
            "registry",
            invalid.clone(),
            Precondition::Absent,
            WriteOptions::new(),
        )
        .await?;

    let error = prepare(&storage)
        .await
        .err()
        .ok_or_else(|| std::io::Error::other("invalid index timestamp must fail closed"))?;

    assert_eq!(error.kind(), ErrorKind::Serialization);
    assert_eq!(
        storage
            .documents()
            .get(V1_JAIL_INDEX_COLLECTION, "registry")
            .await?
            .ok_or_else(|| std::io::Error::other("legacy index preserved"))?
            .doc,
        invalid
    );
    assert!(
        storage
            .documents()
            .get(MIGRATIONS_COLLECTION, JAIL_INDEX_STEP)
            .await?
            .is_none()
    );
    Ok(())
}

#[tokio::test]
async fn deleting_rows_while_scanning_does_not_skip_a_later_page() -> TestResult {
    let storage = storage("tinybox-migrate-pages")?;
    for index in 0..180 {
        let id = format!("box-{index:03}");
        seed_legacy(&storage, &id, old_box(&id), None).await?;
    }

    prepare(&storage).await?;

    let source = storage
        .documents()
        .query_all(V1_BOX_COLLECTION, &Query::all())
        .await?;
    let target = storage
        .documents()
        .query_all(BOX_COLLECTION, &Query::all())
        .await?;
    assert_eq!(source, Vec::<Versioned<Value>>::new());
    assert_eq!(target.len(), 180);
    assert_eq!(target.first().map(|row| row.id.as_str()), Some("box-000"));
    assert_eq!(target.last().map(|row| row.id.as_str()), Some("box-179"));
    let receipt = storage
        .documents()
        .get(MIGRATIONS_COLLECTION, BOXES_STEP)
        .await?
        .ok_or_else(|| std::io::Error::other("completed scan receipt"))?;
    assert_eq!(receipt.doc["complete"], true);
    Ok(())
}

#[tokio::test]
async fn a_backend_query_failure_does_not_write_a_completion_receipt() -> TestResult {
    let storage = storage("tinybox-migrate-query-failure")?;
    seed_legacy(&storage, "b1", old_box("b1"), None).await?;
    let faulty = with_document_fault(
        &storage,
        Faults {
            query: true,
            ..Faults::default()
        },
    );

    assert!(prepare(&faulty).await.is_err());
    assert!(
        storage
            .documents()
            .get(MIGRATIONS_COLLECTION, BOXES_STEP)
            .await?
            .is_none()
    );
    assert!(
        storage
            .documents()
            .get(V1_BOX_COLLECTION, "b1")
            .await?
            .is_some()
    );
    Ok(())
}

#[tokio::test]
async fn an_existing_matching_destination_is_verified_before_source_removal() -> TestResult {
    let storage = storage("tinybox-migrate-matching-destination")?;
    let source = old_box("b1");
    seed_legacy(&storage, "b1", source.clone(), Some(789)).await?;
    storage
        .documents()
        .ensure_collection(&CollectionSpec::new(BOX_COLLECTION))
        .await?;
    storage
        .documents()
        .put_with(
            BOX_COLLECTION,
            "b1",
            box_v1::to_body(source).map_err(std::io::Error::other)?,
            Precondition::Absent,
            WriteOptions::new().schema(BODY_VERSION).expires_ms(789),
        )
        .await?;

    prepare(&storage).await?;

    assert!(
        storage
            .documents()
            .get(V1_BOX_COLLECTION, "b1")
            .await?
            .is_none()
    );
    assert_eq!(
        storage
            .documents()
            .get(BOX_COLLECTION, "b1")
            .await?
            .ok_or_else(|| std::io::Error::other("verified existing target"))?
            .meta
            .expires_ms,
        Some(789)
    );
    Ok(())
}

#[tokio::test]
async fn malformed_receipts_and_failed_target_writes_preserve_migration_sources() -> TestResult {
    let malformed = storage("tinybox-migrate-malformed-receipt")?;
    seed_legacy(&malformed, "b1", old_box("b1"), None).await?;
    malformed
        .documents()
        .ensure_collection(&CollectionSpec::new(MIGRATIONS_COLLECTION))
        .await?;
    malformed
        .documents()
        .put_with(
            MIGRATIONS_COLLECTION,
            BOXES_STEP,
            json!({"step": BOXES_STEP, "version": "future", "complete": true}),
            Precondition::Absent,
            WriteOptions::new().schema(BODY_VERSION),
        )
        .await?;
    assert!(prepare(&malformed).await.is_err());
    assert!(
        malformed
            .documents()
            .get(V1_BOX_COLLECTION, "b1")
            .await?
            .is_some()
    );

    let storage = storage("tinybox-migrate-put-failure")?;
    seed_legacy(&storage, "b1", old_box("b1"), None).await?;
    let faulty = with_document_fault(
        &storage,
        Faults {
            put: true,
            ..Faults::default()
        },
    );
    assert!(prepare(&faulty).await.is_err());
    assert!(
        storage
            .documents()
            .get(V1_BOX_COLLECTION, "b1")
            .await?
            .is_some()
    );
    assert!(
        storage
            .documents()
            .get(BOX_COLLECTION, "b1")
            .await?
            .is_none()
    );
    Ok(())
}
