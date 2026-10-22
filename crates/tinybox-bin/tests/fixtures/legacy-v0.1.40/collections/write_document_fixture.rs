use std::path::PathBuf;

use serde_json::{Value, json};
use tinybox_core::{BoxId, BoxInfo, BoxState, HostRef, Placement, SandboxRef, Store, WorkspaceSource};
use tinybox_drivers::{
    DocumentBoxStore, DocumentIndexStore, JAIL_INDEX_COLLECTION, storage_schema,
};
use tinybox_jail::IndexStore;
use tinystoragedrivers_core::{
    MigrateOptions, MemoryStorage, Registry, Scope, StorageBackend,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let output = PathBuf::from(
        std::env::args_os()
            .nth(1)
            .ok_or("fixture output path required")?,
    );
    std::fs::create_dir_all(&output)?;

    let backend = MemoryStorage::new();
    let registry = Registry::compose([storage_schema()])?;
    registry.prepare(&backend).await?;
    let storage = backend.for_scope(&Scope::local())?;
    registry
        .migrate(&storage, &MigrateOptions::new())
        .await?;

    let boxes = DocumentBoxStore::new(storage.documents().clone())?;
    let box_info = BoxInfo::new(
        BoxId::new("fixture-box")?,
        BoxState::Ready,
        tinybox_core::BoxSpec::new(
            Placement::new(HostRef::new("local")?, SandboxRef::new("passthrough")?),
            WorkspaceSource::LocalDir("/srv/fixture-workspace".into()),
        )
        .with_env("FIXTURE", "public-document-writer"),
    );
    boxes.insert(&box_info)?;

    let index = DocumentIndexStore::new(storage.documents().clone(), "fixture-registry")?;
    index.save(
        br#"{"records":{"jail-fixture":{"id":"jail-fixture","label":"fixture","created_at_unix":1700000000,"updated_at_unix":1700000001}},"schema_version":1}"#,
    )?;

    let box_row = storage
        .documents()
        .get("box.boxes", "fixture-box")
        .await?
        .ok_or("public box writer did not produce a readable row")?;
    let index_row = storage
        .documents()
        .get(JAIL_INDEX_COLLECTION, "fixture-registry")
        .await?
        .ok_or("public index writer did not produce a readable row")?;
    let rows: Vec<Value> = vec![
        json!({
            "collection": "box.boxes",
            "id": box_row.id,
            "body": box_row.doc,
            "schema": box_row.meta.schema,
            "expires_ms": box_row.meta.expires_ms,
        }),
        json!({
            "collection": JAIL_INDEX_COLLECTION,
            "id": index_row.id,
            "body": index_row.doc,
            "schema": index_row.meta.schema,
            "expires_ms": index_row.meta.expires_ms,
        }),
    ];
    std::fs::write(output.join("documents.json"), serde_json::to_vec_pretty(&rows)?)?;
    Ok(())
}
