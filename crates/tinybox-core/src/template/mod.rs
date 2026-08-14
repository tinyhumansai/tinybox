//! Naming a snapshot so it can be started from again.
//!
//! A template is a named snapshot and nothing else — no separate type, no
//! separate storage path, no build step. That is why it is the cheapest of the
//! optimizations tinybox took from the field: the machinery it needs already
//! exists, and `WorkspaceSource::Snapshot` already knows how to start from one.
//!
//! The point is to keep provisioning off the critical path. A template that
//! already has the dependencies installed turns a two-minute `create` into a
//! one-second one, and it does that by moving the work to the moment somebody
//! chose to do it rather than every time a box is made.
//!
//! ```
//! use tinybox_core::template::{MemoryTemplates, Templates};
//! use tinybox_core::{SnapshotId, TemplateName};
//!
//! let templates = MemoryTemplates::new();
//! let name = TemplateName::new("rust-ci")?;
//!
//! templates.save(&name, &SnapshotId::new("sha-9f2c0e1b7a4d")?)?;
//! assert_eq!(templates.get(&name)?.as_str(), "sha-9f2c0e1b7a4d");
//! # Ok::<(), tinybox_core::Error>(())
//! ```

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use crate::error::{Error, Result};
use crate::identity::{SnapshotId, TemplateName};

/// A record of which snapshot each template name points at.
pub trait Templates: std::fmt::Debug + Send + Sync + 'static {
    /// Point `name` at `snapshot`, replacing any previous target.
    ///
    /// Replacing rather than refusing is deliberate: re-saving a template under
    /// the same name after rebuilding it is the normal way to update one.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Store`] when the record cannot be persisted.
    fn save(&self, name: &TemplateName, snapshot: &SnapshotId) -> Result<()>;

    /// What `name` points at.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnknownTemplate`] when `name` has never been saved, and
    /// [`Error::Store`] when the records cannot be read.
    fn get(&self, name: &TemplateName) -> Result<SnapshotId>;

    /// Every template, ordered by name so output is stable.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Store`] when the records cannot be read.
    fn list(&self) -> Result<Vec<(TemplateName, SnapshotId)>>;

    /// Forget `name`.
    ///
    /// The snapshot it pointed at is left alone: other templates or boxes may
    /// still be using it, and this is a name being retired rather than data
    /// being deleted.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnknownTemplate`] when `name` has never been saved.
    fn remove(&self, name: &TemplateName) -> Result<()>;
}

/// Templates held in memory for the life of the process.
#[derive(Debug, Default)]
pub struct MemoryTemplates {
    saved: Mutex<BTreeMap<String, SnapshotId>>,
}

impl MemoryTemplates {
    /// An empty set of templates.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Borrow the records, recovering rather than propagating a poisoned lock.
    fn saved(&self) -> MutexGuard<'_, BTreeMap<String, SnapshotId>> {
        self.saved.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Templates for MemoryTemplates {
    fn save(&self, name: &TemplateName, snapshot: &SnapshotId) -> Result<()> {
        self.saved()
            .insert(name.as_str().to_owned(), snapshot.clone());
        Ok(())
    }

    fn get(&self, name: &TemplateName) -> Result<SnapshotId> {
        self.saved()
            .get(name.as_str())
            .cloned()
            .ok_or_else(|| Error::UnknownTemplate {
                name: name.as_str().to_owned(),
            })
    }

    fn list(&self) -> Result<Vec<(TemplateName, SnapshotId)>> {
        self.saved()
            .iter()
            .map(|(name, snapshot)| Ok((TemplateName::new(name.clone())?, snapshot.clone())))
            .collect()
    }

    fn remove(&self, name: &TemplateName) -> Result<()> {
        self.saved()
            .remove(name.as_str())
            .map(|_| ())
            .ok_or_else(|| Error::UnknownTemplate {
                name: name.as_str().to_owned(),
            })
    }
}

#[cfg(test)]
mod test;
