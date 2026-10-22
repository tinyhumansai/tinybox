//! A jail [`IndexStore`] on the document port.

use std::io;
use std::sync::Arc;

use serde_json::Value;
use tinybox_jail::IndexStore;
use tinystoragedrivers_api::{DocumentStore, Storage};
use tinystoragedrivers_types::{ErrorKind, Key, StorageError, WriteOptions};

use crate::blocking::Blocking;
use crate::migrations;
use crate::repo::Repo;
use tinybox_bus::storage::jail_index as index_body;
use tinybox_bus::storage::{BODY_VERSION, JAIL_INDEX_COLLECTION};

/// A jail registry's index as one document, `box.jail_index/<registry>`.
///
/// The registry serializes the index in its own form (the legacy `index.json`
/// shape); this keeps the equivalent v2 body: the same records with
/// millisecond times and no version field (see the `index_body` module). A
/// document that is not valid JSON reads as [`io::ErrorKind::InvalidData`].
///
/// The collection is declared and migrated by the owner when this store opens.
#[derive(Clone)]
pub struct DocumentIndexStore {
    index: Repo<Value>,
    bridge: Blocking,
    key: String,
    registry: String,
}

impl std::fmt::Debug for DocumentIndexStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DocumentIndexStore")
            .field("registry", &self.registry)
            .finish_non_exhaustive()
    }
}

impl DocumentIndexStore {
    /// Open an index store after `TinyBox`'s owner migrations have completed.
    ///
    /// # Errors
    ///
    /// Returns an error when the declaration or migration fails, the bridge
    /// cannot start, or `registry` cannot be a document id.
    pub async fn open(storage: Storage, registry: impl Into<String>) -> io::Result<Self> {
        migrations::prepare(&storage)
            .await
            .map_err(|error| to_io(&error))?;
        let documents: Arc<dyn DocumentStore> = Arc::clone(storage.documents());
        let registry = registry.into();
        let bridge = Blocking::new().map_err(|e| to_io(&e))?;
        let key = Key::new(registry.as_str())
            .map_err(|e| to_io(&e))?
            .as_str()
            .to_owned();
        let index = Repo::new(&documents, JAIL_INDEX_COLLECTION)
            .map_err(|e| to_io(&e))?
            .with_options(WriteOptions::new().schema(BODY_VERSION));
        Ok(Self {
            index,
            bridge,
            key,
            registry,
        })
    }
}

fn to_io(error: &StorageError) -> io::Error {
    let kind = match error.kind() {
        ErrorKind::Serialization => io::ErrorKind::InvalidData,
        ErrorKind::NotFound => io::ErrorKind::NotFound,
        _ => io::ErrorKind::Other,
    };
    io::Error::new(kind, error.to_string())
}

impl IndexStore for DocumentIndexStore {
    fn load(&self) -> io::Result<Option<Vec<u8>>> {
        let index = self.index.clone();
        let key = self.key.clone();
        let found = self
            .bridge
            .run(async move { index.get(&key).await })
            .and_then(|inner| inner)
            .map_err(|e| to_io(&e))?;
        found
            .map(|entry| {
                serde_json::to_vec(&index_body::from_body(entry.doc))
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
            })
            .transpose()
    }

    fn save(&self, bytes: &[u8]) -> io::Result<()> {
        let registry_form: Value = serde_json::from_slice(bytes)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let body = index_body::to_body(registry_form)?;
        let index = self.index.clone();
        let key = self.key.clone();
        self.bridge
            .run(async move { index.put(&key, &body).await })
            .and_then(|inner| inner)
            .map(|_| ())
            .map_err(|e| to_io(&e))
    }
}

#[cfg(test)]
#[path = "index_store_tests.rs"]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests;
