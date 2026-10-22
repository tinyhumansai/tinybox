//! The module's handle on the host's storage, reached over the storage bus.
//!
//! The module owns no storage backend, file or path. Box records and the jail
//! index go through [`tinybox_drivers`] on the document port the host serves;
//! the host binds the scope from the authenticated caller, so nothing here
//! names one. If the host does not serve storage, durable box operations fail
//! closed; the module never substitutes private in-memory records.

use std::sync::Arc;

use tinybox_core::{Error, Store};
use tinybus::Connection;
#[cfg(test)]
use tinystoragedrivers_api::DocumentStore;
use tinystoragedrivers_api::Storage;

/// Lazily connected storage for one module instance.
#[derive(Default)]
pub(super) struct ModuleStorage {
    connection: Option<Connection>,
    #[cfg(test)]
    test_storage: Option<Storage>,
    scoped: tokio::sync::Mutex<Option<Storage>>,
    /// The opened host-backed box store, shared by every resource: it owns a
    /// blocking bridge with its own runtime thread, so one per module.
    boxes: tokio::sync::Mutex<Option<Arc<dyn Store>>>,
}

impl ModuleStorage {
    /// Storage reached through `connection`.
    pub(super) fn connected(connection: Connection) -> Self {
        Self {
            connection: Some(connection),
            scoped: tokio::sync::Mutex::default(),
            boxes: tokio::sync::Mutex::default(),
            #[cfg(test)]
            test_storage: None,
        }
    }

    /// Directly bound testkit storage for resource unit tests.
    #[cfg(test)]
    pub(super) fn with_test_storage(storage: Storage) -> Self {
        Self {
            test_storage: Some(storage),
            ..Self::default()
        }
    }

    /// The host-bound handle, connected on first use and shared afterwards.
    ///
    /// A failed connect is not cached, so a host that starts serving storage
    /// later is picked up by the next call.
    async fn scoped(&self) -> Option<Storage> {
        #[cfg(test)]
        if let Some(storage) = &self.test_storage {
            return Some(storage.clone());
        }
        let connection = self.connection.clone()?;
        let mut slot = self.scoped.lock().await;
        if let Some(scoped) = slot.as_ref() {
            return Some(scoped.clone());
        }
        let bus = match tinystoragedrivers_busproxy::connect_storage(connection).await {
            Ok(bus) => bus,
            Err(error) => {
                log::debug!("[tinybox_module] storage bus unavailable: {error}");
                return None;
            }
        };
        log::debug!("[tinybox_module] storage bus connected");
        *slot = Some(bus.clone());
        Some(bus)
    }

    /// The host's document port, when it serves one.
    #[cfg(test)]
    pub(super) async fn documents(&self) -> Option<Arc<dyn DocumentStore>> {
        self.scoped()
            .await
            .map(|storage| Arc::clone(storage.documents()))
    }

    /// Open durable box records on the host's document port.
    ///
    /// # Errors
    ///
    /// Returns an error when the host is absent or its storage cannot be opened.
    pub(super) async fn box_store(&self) -> tinybox_core::Result<Arc<dyn Store>> {
        let storage = self.scoped().await.ok_or_else(|| Error::Store {
            operation: "open",
            message: "the host did not provide storage".to_owned(),
        })?;
        let mut slot = self.boxes.lock().await;
        if let Some(store) = slot.as_ref() {
            return Ok(Arc::clone(store));
        }
        let opened = tinybox_drivers::DocumentBoxStore::open(storage)
            .await
            .inspect_err(|error| {
                log::warn!("[tinybox_module] box store on host storage unavailable: {error}");
            })?;
        let store: Arc<dyn Store> = Arc::new(OffWorkerStore(opened));
        *slot = Some(Arc::clone(&store));
        Ok(store)
    }

    /// A jail registry rooted at `base` whose index lives on the host's
    /// document port, or `None` when the host serves no storage.
    #[cfg(test)]
    pub(super) async fn jail_registry(
        &self,
        base: std::path::PathBuf,
        name: String,
    ) -> Option<std::io::Result<tinybox_jail::JailRegistry>> {
        let storage = self.scoped().await?;
        let index = tinybox_drivers::DocumentIndexStore::open(storage, name).await;
        let opened = tokio::task::spawn_blocking(move || {
            let index = index?;
            tinybox_jail::JailRegistry::open_with_store(
                base,
                Arc::new(tinybox_core::clock::SystemClock::new()),
                Arc::new(index),
            )
        })
        .await;
        Some(opened.unwrap_or_else(|error| Err(std::io::Error::other(error))))
    }
}

/// A [`Store`] whose every call may block on a bus reply, run so the runtime
/// worker that drives the same connection stays free.
///
/// The module runs on one worker thread; a blocking bridge on that worker would
/// wait for a reply only that worker can deliver. On a multi-thread runtime,
/// `block_in_place` hands the worker's queue to a replacement thread for the
/// duration of the call.
#[derive(Debug)]
struct OffWorkerStore<S>(S);

impl<S> OffWorkerStore<S> {
    fn off_worker<T>(call: impl FnOnce() -> T) -> T {
        match tokio::runtime::Handle::try_current() {
            Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
                tokio::task::block_in_place(call)
            }
            _ => call(),
        }
    }
}

impl<S: Store> Store for OffWorkerStore<S> {
    fn insert(&self, info: &tinybox_core::BoxInfo) -> tinybox_core::Result<()> {
        Self::off_worker(|| self.0.insert(info))
    }

    fn get(&self, id: &tinybox_core::BoxId) -> tinybox_core::Result<tinybox_core::BoxInfo> {
        Self::off_worker(|| self.0.get(id))
    }

    fn list(&self) -> tinybox_core::Result<Vec<tinybox_core::BoxInfo>> {
        Self::off_worker(|| self.0.list())
    }

    fn set_state(
        &self,
        id: &tinybox_core::BoxId,
        state: tinybox_core::BoxState,
    ) -> tinybox_core::Result<()> {
        Self::off_worker(|| self.0.set_state(id, state))
    }

    fn remove(&self, id: &tinybox_core::BoxId) -> tinybox_core::Result<()> {
        Self::off_worker(|| self.0.remove(id))
    }
}

/// A view of a shared [`Store`] that remembers the records this holder
/// inserted, so a failed create can find its own record by identity rather
/// than by diffing a collection other resources write to.
#[derive(Debug)]
pub(super) struct RecordingStore {
    inner: Arc<dyn Store>,
    inserted: std::sync::Mutex<Vec<tinybox_core::BoxId>>,
}

impl RecordingStore {
    /// A recording view over `inner`.
    pub(super) fn new(inner: Arc<dyn Store>) -> Self {
        Self {
            inner,
            inserted: std::sync::Mutex::default(),
        }
    }

    /// The first id this view inserted that the store may still hold.
    ///
    /// Only a definite `UnknownBox` drops an id; a read that fails for another
    /// reason keeps it, so a transient error cannot orphan the record.
    pub(super) fn first_inserted(&self) -> Option<tinybox_core::BoxId> {
        let ids = self
            .inserted
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        ids.into_iter().find(|id| {
            !matches!(
                self.inner.get(id),
                Err(tinybox_core::Error::UnknownBox { .. })
            )
        })
    }
}

impl Store for RecordingStore {
    fn insert(&self, info: &tinybox_core::BoxInfo) -> tinybox_core::Result<()> {
        self.inner.insert(info)?;
        self.inserted
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(info.id.clone());
        Ok(())
    }

    fn get(&self, id: &tinybox_core::BoxId) -> tinybox_core::Result<tinybox_core::BoxInfo> {
        self.inner.get(id)
    }

    fn list(&self) -> tinybox_core::Result<Vec<tinybox_core::BoxInfo>> {
        self.inner.list()
    }

    fn set_state(
        &self,
        id: &tinybox_core::BoxId,
        state: tinybox_core::BoxState,
    ) -> tinybox_core::Result<()> {
        self.inner.set_state(id, state)
    }

    fn remove(&self, id: &tinybox_core::BoxId) -> tinybox_core::Result<()> {
        self.inner.remove(id)?;
        // A freed id can be reissued to another resource; it is no longer ours.
        self.inserted
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|held| held != id);
        Ok(())
    }
}

impl std::fmt::Debug for ModuleStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ModuleStorage")
            .field("connected", &self.connection.is_some())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
#[path = "storage_tests.rs"]
mod tests;
