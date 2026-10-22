//! A typed collection handle with optimistic update retries.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;

use serde::{Serialize, de::DeserializeOwned};
use tinystoragedrivers_api::DocumentStore;
use tinystoragedrivers_types::{
    ErrorKind, Page, Precondition, Query, Result, StorageError, Version, Versioned, WriteOptions,
    validate_collection,
};

/// Typed access to a single collection in one scope.
pub(crate) struct Repo<T> {
    docs: Arc<dyn DocumentStore>,
    collection: String,
    options: WriteOptions,
    attempts: u32,
    backoff: Duration,
    marker: PhantomData<fn() -> T>,
}

impl<T> Clone for Repo<T> {
    fn clone(&self) -> Self {
        Self {
            docs: Arc::clone(&self.docs),
            collection: self.collection.clone(),
            options: self.options,
            attempts: self.attempts,
            backoff: self.backoff,
            marker: PhantomData,
        }
    }
}

impl<T> std::fmt::Debug for Repo<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Repo")
            .field("collection", &self.collection)
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}

impl<T> Repo<T> {
    /// Bind a typed repository to a collection.
    pub(crate) fn new(
        docs: &Arc<dyn DocumentStore>,
        collection: impl Into<String>,
    ) -> Result<Self> {
        let collection = collection.into();
        validate_collection(&collection)?;
        Ok(Self {
            docs: Arc::clone(docs),
            collection,
            options: WriteOptions::default(),
            attempts: 32,
            backoff: Duration::from_millis(1),
            marker: PhantomData,
        })
    }

    /// Attach schema/expiry options to every write through this repository.
    pub(crate) fn with_options(mut self, options: WriteOptions) -> Self {
        self.options = options;
        self
    }
}

impl<T: Serialize + DeserializeOwned + Send + Sync> Repo<T> {
    pub(crate) async fn get(&self, id: &str) -> Result<Option<Versioned<T>>> {
        self.docs
            .get(&self.collection, id)
            .await?
            .map(decode)
            .transpose()
    }

    pub(crate) async fn put(&self, id: &str, value: &T) -> Result<Version> {
        self.write(id, value, Precondition::None).await
    }

    pub(crate) async fn insert(&self, id: &str, value: &T) -> Result<Version> {
        self.write(id, value, Precondition::Absent).await
    }

    pub(crate) async fn delete(&self, id: &str) -> Result<bool> {
        self.docs
            .delete(&self.collection, id, Precondition::None)
            .await
    }

    pub(crate) async fn query(&self, query: &Query) -> Result<Page<Versioned<T>>> {
        let page = self.docs.query(&self.collection, query).await?;
        Ok(Page {
            items: page
                .items
                .into_iter()
                .map(decode)
                .collect::<Result<Vec<_>>>()?,
            next: page.next,
        })
    }

    pub(crate) async fn update<F>(&self, id: &str, mut update: F) -> Result<Option<(T, Version)>>
    where
        F: FnMut(Option<T>) -> Result<Option<T>> + Send,
    {
        for attempt in 0..self.attempts.max(1) {
            let (precondition, current) = match self.docs.get(&self.collection, id).await? {
                Some(found) => {
                    let found = decode(found)?;
                    (Precondition::Version(found.version), Some(found.doc))
                }
                None => (Precondition::Absent, None),
            };
            let Some(next) = update(current)? else {
                return Ok(None);
            };
            match self.write(id, &next, precondition).await {
                Ok(version) => return Ok(Some((next, version))),
                Err(error) if error.kind() == ErrorKind::Conflict => {
                    if attempt + 1 == self.attempts.max(1) {
                        return Err(error);
                    }
                    let shift = attempt.min(10);
                    let cap = self.backoff.saturating_mul(1_u32 << shift);
                    let nanos = u64::try_from(cap.as_nanos()).unwrap_or(u64::MAX);
                    if nanos > 0 {
                        let half = nanos / 2;
                        let jitter = RandomState::new().build_hasher().finish();
                        tokio::time::sleep(Duration::from_nanos(
                            half + jitter % (nanos - half + 1),
                        ))
                        .await;
                    }
                }
                Err(error) => return Err(error),
            }
        }
        Err(StorageError::conflict(
            "repository update retry budget exhausted",
        ))
    }

    async fn write(&self, id: &str, value: &T, precondition: Precondition) -> Result<Version> {
        let body = serde_json::to_value(value)
            .map_err(|error| StorageError::serialization(error.to_string()))?;
        self.docs
            .put_with(&self.collection, id, body, precondition, self.options)
            .await
    }
}

fn decode<T: DeserializeOwned>(found: Versioned<serde_json::Value>) -> Result<Versioned<T>> {
    let doc = serde_json::from_value(found.doc)
        .map_err(|error| StorageError::serialization(error.to_string()))?;
    Ok(Versioned {
        id: found.id,
        version: found.version,
        doc,
        meta: found.meta,
    })
}
