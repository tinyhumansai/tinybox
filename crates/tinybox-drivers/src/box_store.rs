//! A [`Store`] on the document port.

use std::sync::Arc;

use tinybox_core::{BoxId, BoxInfo, BoxState, Error, Result, Store};
use tinystoragedrivers_api::{DocumentStore, Storage};
use tinystoragedrivers_types::{ErrorKind, Key, Query, StorageError, WriteOptions};

use crate::blocking::Blocking;
use crate::migrations;
use crate::record::{BoxRecord, StateRecord};
use crate::repo::Repo;
use tinybox_bus::storage::{BODY_VERSION, BOX_COLLECTION};

/// Box records as documents, `box.boxes/<box id>`.
///
/// Inserts use an absent-only precondition, so two processes racing for one
/// name resolve to a [`Error::DuplicateBox`] for the loser (which
/// [`insert_new`](tinybox_core::store::insert_new) retries). State changes are
/// one compare-and-swap loop on the document version, so
/// they never overwrite a concurrent change.
///
/// The collection is declared and migrated by the owner when this store opens.
#[derive(Clone)]
pub struct DocumentBoxStore {
    boxes: Repo<BoxRecord>,
    bridge: Blocking,
}

impl std::fmt::Debug for DocumentBoxStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DocumentBoxStore").finish_non_exhaustive()
    }
}

impl DocumentBoxStore {
    /// Open a store and migrate legacy box documents before returning it.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Store`] when declarations, migrations, or the bridge
    /// cannot be opened.
    pub async fn open(storage: Storage) -> Result<Self> {
        migrations::prepare(&storage)
            .await
            .map_err(|error| store_error("open", &error))?;
        let documents: Arc<dyn DocumentStore> = Arc::clone(storage.documents());
        let bridge = Blocking::new().map_err(|error| store_error("open", &error))?;
        let boxes = Repo::new(&documents, BOX_COLLECTION)
            .map_err(|error| store_error("open", &error))?
            .with_options(WriteOptions::new().schema(BODY_VERSION));
        log::debug!("[tinybox_drivers] box store ready collection={BOX_COLLECTION}");
        Ok(Self { boxes, bridge })
    }

    fn run<T, F>(&self, operation: &'static str, future: F) -> Result<T>
    where
        F: std::future::Future<Output = std::result::Result<T, StorageError>> + Send + 'static,
        T: Send + 'static,
    {
        self.bridge
            .run(future)
            .and_then(|inner| inner)
            .map_err(|error| store_error(operation, &error))
    }
}

fn store_error(operation: &'static str, error: &StorageError) -> Error {
    Error::Store {
        operation,
        message: error.to_string(),
    }
}

fn key(id: &BoxId) -> Result<String> {
    Key::new(id.as_str())
        .map(|key| key.as_str().to_owned())
        .map_err(|error| store_error("key", &error))
}

fn unknown(id: &BoxId) -> Error {
    Error::UnknownBox {
        id: id.as_str().to_owned(),
    }
}

/// The record stored under document id `key`, as a model record.
fn decode(key: &str, record: BoxRecord) -> Result<BoxInfo> {
    let id = BoxId::new(key).map_err(|error| Error::Store {
        operation: "decode",
        message: error.to_string(),
    })?;
    Ok(record.into_info(id))
}

/// Document ids and bodies are read through serde, so a body that is not a
/// [`BoxRecord`] arrives as a serialization error; report it as a decode.
fn read_error(operation: &'static str, error: &StorageError) -> Error {
    if error.kind() == ErrorKind::Serialization {
        store_error("decode", error)
    } else {
        store_error(operation, error)
    }
}

impl Store for DocumentBoxStore {
    fn insert(&self, info: &BoxInfo) -> Result<()> {
        let record = BoxRecord::try_from(info)?;
        let key = key(&info.id)?;
        let boxes = self.boxes.clone();
        let outcome = self
            .bridge
            .run(async move { boxes.insert(&key, &record).await });
        match outcome.and_then(|inner| inner) {
            Ok(_) => Ok(()),
            Err(error)
                if matches!(error.kind(), ErrorKind::AlreadyExists | ErrorKind::Conflict) =>
            {
                Err(Error::DuplicateBox {
                    id: info.id.as_str().to_owned(),
                })
            }
            Err(error) => Err(store_error("insert", &error)),
        }
    }

    fn get(&self, id: &BoxId) -> Result<BoxInfo> {
        let key = key(id)?;
        let boxes = self.boxes.clone();
        let lookup = key.clone();
        let found = self
            .bridge
            .run(async move { boxes.get(&lookup).await })
            .and_then(|inner| inner)
            .map_err(|error| read_error("read", &error))?;
        let found = found.ok_or_else(|| unknown(id))?;
        decode(&key, found.doc)
    }

    fn list(&self) -> Result<Vec<BoxInfo>> {
        let boxes = self.boxes.clone();
        let found = self
            .bridge
            .run(async move {
                let mut query = Query::default();
                let mut all = Vec::new();
                loop {
                    let page = boxes.query(&query).await?;
                    all.extend(page.items);
                    match page.next {
                        Some(cursor) => query.cursor = Some(cursor),
                        None => return Ok(all),
                    }
                }
            })
            .and_then(|inner: std::result::Result<Vec<_>, StorageError>| inner)
            .map_err(|error| read_error("list", &error))?;
        // Documents come back ordered by id; keep that so output is stable.
        found
            .into_iter()
            .map(|entry| decode(&entry.id, entry.doc))
            .collect()
    }

    fn set_state(&self, id: &BoxId, state: BoxState) -> Result<()> {
        let state = StateRecord::try_from(state)?;
        let key = key(id)?;
        let boxes = self.boxes.clone();
        let updated = self
            .bridge
            .run(async move {
                boxes
                    .update(&key, |current| {
                        Ok(current.map(|mut record| {
                            record.state = state;
                            record
                        }))
                    })
                    .await
            })
            .and_then(|inner| inner)
            .map_err(|error| read_error("update", &error))?;
        // The loop leaves a missing record alone.
        updated.map(|_| ()).ok_or_else(|| unknown(id))
    }

    fn remove(&self, id: &BoxId) -> Result<()> {
        let key = key(id)?;
        let boxes = self.boxes.clone();
        let removed = self.run("remove", async move { boxes.delete(&key).await })?;
        if removed { Ok(()) } else { Err(unknown(id)) }
    }
}

#[cfg(test)]
#[path = "box_store_tests.rs"]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests;
