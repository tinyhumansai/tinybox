//! Where box records live between operations.
//!
//! A sandbox is not the owner of the fact that a box exists. The CLI creates a
//! box in one process and executes in it from another, so the record has to
//! outlive both — which is why [`Sandbox`](crate::runtime::Sandbox)
//! implementations take a [`Store`] rather than keeping their own map.
//!
//! The trait is deliberately synchronous. Every implementation is either a
//! memory map or a small local file; making it async would push executor
//! choice onto every caller for no gain.
//!
//! [`MemoryStore`] is the implementation for tests and for a single-process
//! run. A persisting implementation lives with the CLI, which is the only part
//! of tinybox that needs boxes to survive a process exit.
//!
//! ```
//! use tinybox_core::store::{MemoryStore, Store};
//! use tinybox_core::{BoxId, BoxInfo, BoxState};
//! # use tinybox_core::{BoxSpec, HostRef, Placement, SandboxRef, WorkspaceSource};
//!
//! let store = MemoryStore::new();
//! # let spec = BoxSpec::new(
//! #     Placement::new(HostRef::new("local")?, SandboxRef::new("passthrough")?),
//! #     WorkspaceSource::LocalDir("/tmp".into()),
//! # );
//! let info = BoxInfo::new(BoxId::new("build-1")?, BoxState::Ready, spec);
//!
//! store.insert(&info)?;
//! assert_eq!(store.get(&info.id)?.state, BoxState::Ready);
//! assert_eq!(store.list()?.len(), 1);
//! # Ok::<(), tinybox_core::Error>(())
//! ```

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use crate::error::{Error, Result};
use crate::identity::BoxId;
use crate::runtime::{BoxInfo, BoxState};

/// A record of the boxes a sandbox knows about.
///
/// Implementations must be safe to share across threads; a sandbox holds one
/// behind an `Arc` and may be called concurrently.
pub trait Store: Send + Sync + std::fmt::Debug + 'static {
    /// Record a new box.
    ///
    /// # Errors
    ///
    /// Returns [`Error::DuplicateBox`] when `info.id` is already present, and
    /// [`Error::Store`] when the record cannot be persisted.
    fn insert(&self, info: &BoxInfo) -> Result<()>;

    /// Look up one box.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnknownBox`] when `id` does not resolve, and
    /// [`Error::Store`] when the records cannot be read.
    fn get(&self, id: &BoxId) -> Result<BoxInfo>;

    /// Every box, ordered by identifier so output is stable.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Store`] when the records cannot be read.
    fn list(&self) -> Result<Vec<BoxInfo>>;

    /// Move a box to a new state.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnknownBox`] when `id` does not resolve, and
    /// [`Error::Store`] when the record cannot be persisted.
    fn set_state(&self, id: &BoxId, state: BoxState) -> Result<()>;

    /// Forget a box.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnknownBox`] when `id` does not resolve, and
    /// [`Error::Store`] when the record cannot be persisted.
    fn remove(&self, id: &BoxId) -> Result<()>;

    /// An identifier no box currently holds.
    ///
    /// The default takes the lowest free `box-N`, which keeps identifiers
    /// short, readable, and reproducible — a property the tests depend on and
    /// randomness would destroy.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Store`] when the records cannot be read, and
    /// [`Error::InvalidIdentifier`] if the generated name is somehow invalid.
    fn allocate_id(&self) -> Result<BoxId> {
        let taken = self
            .list()?
            .into_iter()
            .map(|info| info.id.into_string())
            .collect::<std::collections::BTreeSet<_>>();

        (0..=taken.len())
            .map(|index| format!("box-{index}"))
            .find(|candidate| !taken.contains(candidate))
            .ok_or_else(|| Error::Store {
                operation: "allocate",
                message: "no identifier was free".to_owned(),
            })
            .and_then(BoxId::new)
    }
}

/// A [`Store`] that keeps records in memory for the life of the process.
///
/// Correct for tests and for a single-process run, and wrong for anything that
/// must survive a process exit.
#[derive(Debug, Default)]
pub struct MemoryStore {
    boxes: Mutex<BTreeMap<String, BoxInfo>>,
}

impl MemoryStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Borrow the records, recovering rather than propagating a poisoned lock.
    ///
    /// A test that panics mid-assertion should not turn every later access into
    /// a second, confusing failure.
    fn records(&self) -> MutexGuard<'_, BTreeMap<String, BoxInfo>> {
        self.boxes.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Store for MemoryStore {
    fn insert(&self, info: &BoxInfo) -> Result<()> {
        let mut records = self.records();
        if records.contains_key(info.id.as_str()) {
            return Err(Error::DuplicateBox {
                id: info.id.as_str().to_owned(),
            });
        }
        records.insert(info.id.as_str().to_owned(), info.clone());
        Ok(())
    }

    fn get(&self, id: &BoxId) -> Result<BoxInfo> {
        self.records()
            .get(id.as_str())
            .cloned()
            .ok_or_else(|| Error::UnknownBox {
                id: id.as_str().to_owned(),
            })
    }

    fn list(&self) -> Result<Vec<BoxInfo>> {
        Ok(self.records().values().cloned().collect())
    }

    fn set_state(&self, id: &BoxId, state: BoxState) -> Result<()> {
        let mut records = self.records();
        let info = records
            .get_mut(id.as_str())
            .ok_or_else(|| Error::UnknownBox {
                id: id.as_str().to_owned(),
            })?;
        info.state = state;
        Ok(())
    }

    fn remove(&self, id: &BoxId) -> Result<()> {
        self.records()
            .remove(id.as_str())
            .map(|_| ())
            .ok_or_else(|| Error::UnknownBox {
                id: id.as_str().to_owned(),
            })
    }
}

#[cfg(test)]
mod test;
