//! Snapshot templates stored as TinyBox-owned documents.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tinybox_core::{Error, Result, SnapshotId, TemplateName, Templates};
use tinystoragedrivers_api::{DocumentStore, Storage};
use tinystoragedrivers_types::{Key, Query, StorageError, WriteOptions};

use crate::blocking::Blocking;
use crate::migrations;
use crate::repo::Repo;
use tinybox_bus::storage::{BODY_VERSION, TEMPLATE_COLLECTION};

/// Snapshot template names stored in `box.templates`.
#[derive(Clone)]
pub struct DocumentTemplateStore {
    templates: Repo<TemplateRecord>,
    bridge: Blocking,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TemplateRecord {
    snapshot: SnapshotId,
}

impl std::fmt::Debug for DocumentTemplateStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DocumentTemplateStore")
            .finish_non_exhaustive()
    }
}

impl DocumentTemplateStore {
    /// Open the template store after `TinyBox` declarations and migrations.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Store`] when storage preparation or the bridge fails.
    pub async fn open(storage: Storage) -> Result<Self> {
        migrations::prepare(&storage)
            .await
            .map_err(|error| store_error("open", &error))?;
        let documents: Arc<dyn DocumentStore> = Arc::clone(storage.documents());
        let bridge = Blocking::new().map_err(|error| store_error("open", &error))?;
        let templates = Repo::new(&documents, TEMPLATE_COLLECTION)
            .map_err(|error| store_error("open", &error))?
            .with_options(WriteOptions::new().schema(BODY_VERSION));
        Ok(Self { templates, bridge })
    }

    /// Import a legacy template without replacing a value another writer has
    /// already stored under the same name.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Store`] when the row cannot be inserted or when an
    /// existing row points at a different snapshot.
    pub fn import_if_missing(&self, name: &TemplateName, snapshot: &SnapshotId) -> Result<()> {
        let key = template_key(name)?;
        let templates = self.templates.clone();
        let record = TemplateRecord {
            snapshot: snapshot.clone(),
        };
        self.run("import", async move {
            match templates.insert(&key, &record).await {
                Ok(_) => Ok(()),
                Err(error) if error.kind() == tinystoragedrivers_types::ErrorKind::Conflict => {
                    let found = templates.get(&key).await?;
                    match found {
                        Some(found) if found.doc == record => Ok(()),
                        Some(_) => Err(StorageError::conflict(
                            "legacy template conflicts with the stored record",
                        )),
                        None => Err(StorageError::conflict(
                            "legacy template disappeared during import",
                        )),
                    }
                }
                Err(error) => Err(error),
            }
        })
    }

    fn run<T, F>(&self, operation: &'static str, future: F) -> Result<T>
    where
        F: std::future::Future<Output = std::result::Result<T, StorageError>> + Send + 'static,
        T: Send + 'static,
    {
        self.bridge
            .run(future)
            .and_then(|result| result)
            .map_err(|error| store_error(operation, &error))
    }
}

fn store_error(operation: &'static str, error: &StorageError) -> Error {
    Error::Store {
        operation,
        message: error.to_string(),
    }
}

fn template_key(name: &TemplateName) -> Result<String> {
    Key::new(name.as_str())
        .map(|key| key.as_str().to_owned())
        .map_err(|error| store_error("key", &error))
}

impl Templates for DocumentTemplateStore {
    fn save(&self, name: &TemplateName, snapshot: &SnapshotId) -> Result<()> {
        let key = template_key(name)?;
        let templates = self.templates.clone();
        let record = TemplateRecord {
            snapshot: snapshot.clone(),
        };
        self.run("save", async move { templates.put(&key, &record).await })
            .map(|_| ())
    }

    fn get(&self, name: &TemplateName) -> Result<SnapshotId> {
        let key = template_key(name)?;
        let templates = self.templates.clone();
        self.run("read", async move { templates.get(&key).await })?
            .map(|found| found.doc.snapshot)
            .ok_or_else(|| Error::UnknownTemplate {
                name: name.as_str().to_owned(),
            })
    }

    fn list(&self) -> Result<Vec<(TemplateName, SnapshotId)>> {
        let templates = self.templates.clone();
        let found = self.run("list", async move {
            let mut query = Query::all();
            let mut all = Vec::new();
            loop {
                let page = templates.query(&query).await?;
                all.extend(page.items);
                match page.next {
                    Some(cursor) => query.cursor = Some(cursor),
                    None => return Ok(all),
                }
            }
        })?;
        found
            .into_iter()
            .map(|entry| Ok((TemplateName::new(entry.id)?, entry.doc.snapshot)))
            .collect()
    }

    fn remove(&self, name: &TemplateName) -> Result<()> {
        let key = template_key(name)?;
        let templates = self.templates.clone();
        let removed = self.run("remove", async move { templates.delete(&key).await })?;
        if removed {
            Ok(())
        } else {
            Err(Error::UnknownTemplate {
                name: name.as_str().to_owned(),
            })
        }
    }
}

#[cfg(test)]
#[path = "template_store_tests.rs"]
mod tests;
