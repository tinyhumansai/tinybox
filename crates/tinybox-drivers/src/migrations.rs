//! Idempotent TinyBox-owned migrations on the host's document port.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tinystoragedrivers_api::{DocumentStore, DocumentStoreExt, Storage};
use tinystoragedrivers_types::{
    CollectionSpec, ErrorKind, Precondition, Query, Result, StorageError, Versioned, WriteOptions,
};

use tinybox_bus::storage::{
    BODY_VERSION, MIGRATIONS_COLLECTION, V1_BOX_COLLECTION, V1_JAIL_INDEX_COLLECTION, box_v1,
    collections, jail_index,
};

const BOXES_STEP: &str = "boxes-v1-to-v2";
const JAIL_INDEX_STEP: &str = "jail-index-v1-to-v2";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MigrationReceipt {
    step: String,
    version: u32,
    complete: bool,
}

/// Ensure `TinyBox`'s current declarations, and nothing else.
///
/// This is all a host-managed port gets ([`DocumentBoxStore::open_host_managed`]
/// and its siblings): the host declared these collections when it bound the
/// module's scope, so the call only confirms host and module agree on them. The
/// host's grant does not include the v1 source collections, and the host's own
/// import owns their migration.
///
/// [`DocumentBoxStore::open_host_managed`]: crate::DocumentBoxStore::open_host_managed
pub(crate) async fn declare(storage: &Storage) -> Result<()> {
    let documents = storage.documents();
    for declaration in collections() {
        documents
            .ensure_collection(&CollectionSpec::new(declaration.name))
            .await?;
    }
    Ok(())
}

/// Ensure `TinyBox`'s declarations and migrate every known legacy row.
///
/// Migration receipts record successful scans. Legacy rows are still scanned
/// on every open so a delayed old writer cannot leave an unreadable record
/// behind a stale completion marker.
pub(crate) async fn prepare(storage: &Storage) -> Result<()> {
    declare(storage).await?;
    let documents = Arc::clone(storage.documents());
    documents
        .ensure_collection(&CollectionSpec::new(V1_BOX_COLLECTION))
        .await?;
    documents
        .ensure_collection(&CollectionSpec::new(V1_JAIL_INDEX_COLLECTION))
        .await?;

    // Validate every owner receipt before changing any source row. A damaged
    // or future receipt must never be silently overwritten by this version.
    validate_receipt(&documents, BOXES_STEP).await?;
    validate_receipt(&documents, JAIL_INDEX_STEP).await?;

    migrate_collection(
        &documents,
        BOXES_STEP,
        V1_BOX_COLLECTION,
        tinybox_bus::storage::BOX_COLLECTION,
        |id, body| {
            if body.get("id").and_then(Value::as_str) != Some(id) {
                return Err(StorageError::serialization(
                    "legacy box id does not match its document key",
                ));
            }
            box_v1::to_body(body).map_err(|error| {
                StorageError::serialization(format!("legacy box row is invalid: {error}"))
            })
        },
    )
    .await?;
    migrate_collection(
        &documents,
        JAIL_INDEX_STEP,
        V1_JAIL_INDEX_COLLECTION,
        tinybox_bus::storage::JAIL_INDEX_COLLECTION,
        |_, body| {
            jail_index::to_body(body).map_err(|error| {
                StorageError::serialization(format!("legacy jail index is invalid: {error}"))
            })
        },
    )
    .await
}

async fn migrate_collection(
    documents: &Arc<dyn DocumentStore>,
    step: &'static str,
    source: &'static str,
    target: &'static str,
    convert: impl Fn(&str, Value) -> Result<Value>,
) -> Result<()> {
    let rows = documents.query_all(source, &Query::all()).await?;
    for row in rows {
        migrate_row(documents, source, target, row, &convert).await?;
    }
    record_complete(documents, step).await
}

async fn migrate_row(
    documents: &Arc<dyn DocumentStore>,
    source: &str,
    target: &str,
    row: Versioned<Value>,
    convert: &impl Fn(&str, Value) -> Result<Value>,
) -> Result<()> {
    let body = convert(&row.id, row.doc.clone())?;
    let options = match row.meta.expires_ms {
        Some(expires_ms) => WriteOptions::new()
            .schema(BODY_VERSION)
            .expires_ms(expires_ms),
        None => WriteOptions::new().schema(BODY_VERSION),
    };
    match documents
        .put_with(target, &row.id, body.clone(), Precondition::Absent, options)
        .await
    {
        Ok(_) => {}
        Err(error) if matches!(error.kind(), ErrorKind::AlreadyExists | ErrorKind::Conflict) => {
            let existing = documents
                .get(target, &row.id)
                .await?
                .ok_or_else(|| StorageError::conflict("migration destination disappeared"))?;
            if existing.doc != body
                || existing.meta.schema != BODY_VERSION
                || existing.meta.expires_ms != row.meta.expires_ms
            {
                return Err(StorageError::conflict(format!(
                    "migration destination `{target}/{}` differs from the legacy row",
                    row.id
                )));
            }
        }
        Err(error) => return Err(error),
    }

    let verified = documents
        .get(target, &row.id)
        .await?
        .ok_or_else(|| StorageError::backend("migration destination was not readable"))?;
    if verified.doc != body
        || verified.meta.schema != BODY_VERSION
        || verified.meta.expires_ms != row.meta.expires_ms
    {
        return Err(StorageError::conflict(format!(
            "migration destination `{target}/{}` failed readback verification",
            row.id
        )));
    }

    if !documents
        .delete(source, &row.id, Precondition::Version(row.version))
        .await?
    {
        let latest = documents.get(source, &row.id).await?;
        if latest.is_some() {
            return Err(StorageError::conflict(format!(
                "legacy row `{source}/{}` changed during migration",
                row.id
            )));
        }
    }
    Ok(())
}

async fn record_complete(documents: &Arc<dyn DocumentStore>, step: &str) -> Result<()> {
    let receipt = MigrationReceipt {
        step: step.to_owned(),
        version: 1,
        complete: true,
    };
    let id = step;
    if validate_receipt(documents, step).await?.is_some() {
        return Ok(());
    }
    let body = serde_json::to_value(receipt)
        .map_err(|error| StorageError::serialization(error.to_string()))?;
    match documents
        .put_with(
            MIGRATIONS_COLLECTION,
            id,
            body.clone(),
            Precondition::Absent,
            WriteOptions::new().schema(BODY_VERSION),
        )
        .await
    {
        Ok(_) => Ok(()),
        Err(error) if error.kind() == ErrorKind::Conflict => {
            let found = documents
                .get_as::<MigrationReceipt>(MIGRATIONS_COLLECTION, id)
                .await?
                .ok_or_else(|| StorageError::conflict("migration receipt disappeared"))?;
            if receipt_is_valid(&found, step) {
                Ok(())
            } else {
                Err(error)
            }
        }
        Err(error) => Err(error),
    }
}

async fn validate_receipt(
    documents: &Arc<dyn DocumentStore>,
    step: &str,
) -> Result<Option<Versioned<MigrationReceipt>>> {
    let Some(receipt) = documents
        .get_as::<MigrationReceipt>(MIGRATIONS_COLLECTION, step)
        .await?
    else {
        return Ok(None);
    };
    if receipt_is_valid(&receipt, step) {
        Ok(Some(receipt))
    } else {
        Err(StorageError::conflict(format!(
            "unsupported or invalid TinyBox migration receipt `{step}`"
        )))
    }
}

fn receipt_is_valid(receipt: &Versioned<MigrationReceipt>, step: &str) -> bool {
    receipt.doc.step == step
        && receipt.doc.version == 1
        && receipt.doc.complete
        && receipt.meta.schema == BODY_VERSION
}

#[cfg(test)]
#[path = "migrations_tests.rs"]
mod tests;
