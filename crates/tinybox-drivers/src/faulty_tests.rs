//! A document port decorator that uses the testkit's shared failure schedule.
//!
//! Compiled only for tests; the happy paths use `MemoryStorage` directly.

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use serde_json::Value;
use tinystoragedrivers_api::DocumentStore;
use tinystoragedrivers_testkit::Failing;
use tinystoragedrivers_types::{
    Capabilities, CollectionSpec, ErrorKind, Filter, Page, Precondition, Query, Sort, StorageError,
    Version, Versioned, WriteOptions,
};

type Result<T> = std::result::Result<T, StorageError>;

/// What to break.
#[derive(Debug, Default, Clone, Copy)]
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct Faults {
    pub(crate) ensure: bool,
    pub(crate) get: bool,
    pub(crate) put: bool,
    pub(crate) delete: bool,
    pub(crate) query: bool,
}

/// Delegates to `inner`, failing the operations named in `faults`.
///
/// `conflicts` forces that many version-checked writes to report a conflict
/// before they reach the inner store (`usize::MAX` means always).
#[derive(Debug)]
pub(crate) struct Faulty {
    pub(crate) inner: Arc<dyn DocumentStore>,
    pub(crate) failing: Failing<dyn DocumentStore>,
    pub(crate) conflicts: AtomicUsize,
    fail_target_readback: bool,
    target_written: std::sync::atomic::AtomicBool,
    source_replacement: Mutex<Option<(String, Value)>>,
    target_replacement: Mutex<Option<(String, Value)>>,
    receipt_race: std::sync::atomic::AtomicBool,
}

impl Faulty {
    pub(crate) fn new(inner: Arc<dyn DocumentStore>, faults: Faults) -> Arc<Self> {
        let failing = Failing::new(Arc::clone(&inner));
        for (enabled, operation) in [
            (faults.ensure, "ensure"),
            (faults.get, "get"),
            (faults.put, "put"),
            (faults.delete, "delete"),
            (faults.query, "query"),
        ] {
            if enabled {
                failing
                    .faults
                    .fail_operation_nth(operation, 1, ErrorKind::Backend);
            }
        }
        Arc::new(Self {
            inner,
            failing,
            conflicts: AtomicUsize::new(0),
            fail_target_readback: false,
            target_written: std::sync::atomic::AtomicBool::new(false),
            source_replacement: Mutex::new(None),
            target_replacement: Mutex::new(None),
            receipt_race: std::sync::atomic::AtomicBool::new(false),
        })
    }

    pub(crate) fn with_conflicts(inner: Arc<dyn DocumentStore>, conflicts: usize) -> Arc<Self> {
        Arc::new(Self {
            failing: Failing::new(Arc::clone(&inner)),
            inner,
            conflicts: AtomicUsize::new(conflicts),
            fail_target_readback: false,
            target_written: std::sync::atomic::AtomicBool::new(false),
            source_replacement: Mutex::new(None),
            target_replacement: Mutex::new(None),
            receipt_race: std::sync::atomic::AtomicBool::new(false),
        })
    }

    pub(crate) fn failing_target_readback(inner: Arc<dyn DocumentStore>) -> Arc<Self> {
        Arc::new(Self {
            failing: Failing::new(Arc::clone(&inner)),
            inner,
            conflicts: AtomicUsize::new(0),
            fail_target_readback: true,
            target_written: std::sync::atomic::AtomicBool::new(false),
            source_replacement: Mutex::new(None),
            target_replacement: Mutex::new(None),
            receipt_race: std::sync::atomic::AtomicBool::new(false),
        })
    }

    pub(crate) fn changing_source_after_target_write(
        inner: Arc<dyn DocumentStore>,
        source_id: String,
        replacement: Value,
    ) -> Arc<Self> {
        Arc::new(Self {
            failing: Failing::new(Arc::clone(&inner)),
            inner,
            conflicts: AtomicUsize::new(0),
            fail_target_readback: false,
            target_written: std::sync::atomic::AtomicBool::new(false),
            source_replacement: Mutex::new(Some((source_id, replacement))),
            target_replacement: Mutex::new(None),
            receipt_race: std::sync::atomic::AtomicBool::new(false),
        })
    }

    pub(crate) fn changing_target_after_write(
        inner: Arc<dyn DocumentStore>,
        target_id: String,
        replacement: Value,
    ) -> Arc<Self> {
        Arc::new(Self {
            failing: Failing::new(Arc::clone(&inner)),
            inner,
            conflicts: AtomicUsize::new(0),
            fail_target_readback: false,
            target_written: std::sync::atomic::AtomicBool::new(false),
            source_replacement: Mutex::new(None),
            target_replacement: Mutex::new(Some((target_id, replacement))),
            receipt_race: std::sync::atomic::AtomicBool::new(false),
        })
    }

    pub(crate) fn racing_receipt(inner: Arc<dyn DocumentStore>) -> Arc<Self> {
        Arc::new(Self {
            failing: Failing::new(Arc::clone(&inner)),
            inner,
            conflicts: AtomicUsize::new(0),
            fail_target_readback: false,
            target_written: std::sync::atomic::AtomicBool::new(false),
            source_replacement: Mutex::new(None),
            target_replacement: Mutex::new(None),
            receipt_race: std::sync::atomic::AtomicBool::new(true),
        })
    }
}

#[async_trait]
impl DocumentStore for Faulty {
    fn capabilities(&self) -> Capabilities {
        self.inner.capabilities()
    }

    async fn ensure_collection(&self, spec: &CollectionSpec) -> Result<()> {
        self.failing
            .call("ensure", self.inner.ensure_collection(spec))
            .await
    }

    async fn get(&self, collection: &str, id: &str) -> Result<Option<Versioned<Value>>> {
        if collection == tinybox_bus::storage::BOX_COLLECTION
            && self.fail_target_readback
            && self.target_written.swap(false, Ordering::SeqCst)
        {
            return Err(StorageError::backend("injected target readback failure"));
        }
        self.failing
            .call("get", self.inner.get(collection, id))
            .await
    }

    async fn put(
        &self,
        collection: &str,
        id: &str,
        doc: Value,
        precondition: Precondition,
    ) -> Result<Version> {
        self.put_with(collection, id, doc, precondition, WriteOptions::default())
            .await
    }

    async fn put_with(
        &self,
        collection: &str,
        id: &str,
        doc: Value,
        precondition: Precondition,
        options: WriteOptions,
    ) -> Result<Version> {
        if collection == tinybox_bus::storage::MIGRATIONS_COLLECTION
            && self.receipt_race.swap(false, Ordering::SeqCst)
            && matches!(precondition, Precondition::Absent)
        {
            self.inner
                .put_with(collection, id, doc, precondition, options)
                .await?;
            return Err(StorageError::conflict("injected concurrent receipt write"));
        }
        if matches!(precondition, Precondition::Version(_)) {
            let left = self.conflicts.load(Ordering::SeqCst);
            if left > 0 {
                if left != usize::MAX {
                    self.conflicts.store(left - 1, Ordering::SeqCst);
                }
                return Err(StorageError::conflict("injected conflict"));
            }
        }
        let version = self
            .failing
            .call(
                "put",
                self.inner
                    .put_with(collection, id, doc, precondition, options),
            )
            .await?;
        if collection == tinybox_bus::storage::BOX_COLLECTION {
            self.target_written.store(true, Ordering::SeqCst);
            let replacement = self
                .target_replacement
                .lock()
                .expect("target replacement mutex")
                .take();
            if let Some((target_id, body)) = replacement
                && let Some(target) = self.inner.get(collection, &target_id).await?
            {
                self.inner
                    .put_with(
                        collection,
                        &target_id,
                        body,
                        Precondition::Version(target.version),
                        options,
                    )
                    .await?;
            }
            let replacement = self
                .source_replacement
                .lock()
                .expect("source replacement mutex")
                .take();
            if let Some((source_id, body)) = replacement
                && let Some(source) = self
                    .inner
                    .get(tinybox_bus::storage::V1_BOX_COLLECTION, &source_id)
                    .await?
            {
                self.inner
                    .put_with(
                        tinybox_bus::storage::V1_BOX_COLLECTION,
                        &source_id,
                        body,
                        Precondition::Version(source.version),
                        WriteOptions::default(),
                    )
                    .await?;
            }
        }
        Ok(version)
    }

    async fn delete(&self, collection: &str, id: &str, precondition: Precondition) -> Result<bool> {
        self.failing
            .call("delete", self.inner.delete(collection, id, precondition))
            .await
    }

    async fn query(&self, collection: &str, query: &Query) -> Result<Page<Versioned<Value>>> {
        self.failing
            .call("query", self.inner.query(collection, query))
            .await
    }

    async fn count(&self, collection: &str, filter: &Filter) -> Result<u64> {
        self.inner.count(collection, filter).await
    }

    async fn delete_where(&self, collection: &str, filter: &Filter) -> Result<u64> {
        self.inner.delete_where(collection, filter).await
    }

    async fn claim(
        &self,
        collection: &str,
        filter: &Filter,
        sort: &[Sort],
        patch: &Value,
    ) -> Result<Option<Versioned<Value>>> {
        self.inner.claim(collection, filter, sort, patch).await
    }

    async fn drop_collection(&self, collection: &str) -> Result<()> {
        self.inner.drop_collection(collection).await
    }
}
