//! A box store that survives the process that wrote it.
//!
//! [`MemoryStore`](tinybox_core::MemoryStore) is enough for a library caller
//! that creates and uses a box in one go. The CLI cannot use it: `tinybox
//! create` and `tinybox exec` are separate processes, so a box recorded by the
//! first has to still exist for the second.
//!
//! Records are held as a single JSON document. That is the right shape at this
//! scale — a handful of boxes per user — and it keeps the file readable, which
//! matters while tinybox is young enough that inspecting state by hand is
//! normal. Identifiers are re-validated on read, so hand-editing cannot
//! introduce a name the constructor would have rejected.
//!
//! # Concurrency
//!
//! Two things protect the file, and they solve different problems.
//!
//! Writes are **atomic**: the document goes to a temporary file in the same
//! directory and is renamed over the target, so a reader sees either the old
//! file or the new one and never a half-written document.
//!
//! Read-modify-write sequences are **locked**: every mutation takes an
//! exclusive advisory lock on a sibling lockfile for its whole duration. Atomic
//! writes alone do not prevent two processes from both reading the same
//! document, each adding a different box, and the second rename discarding the
//! first — a lost record rather than a corrupt file, but lost all the same, and
//! `tinybox create` running in two terminals is not an unusual thing to do.
//!
//! The lock is advisory and held by the kernel, so a process that crashes
//! releases it. A hand-rolled lockfile would strand one behind a crash and need
//! stale-lock detection that is itself a source of bugs.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::path::{Path, PathBuf};

use tinybox_core::{BoxId, BoxInfo, BoxState, Error, Result, Store};

/// A [`Store`] backed by a JSON file on disk.
#[derive(Debug, Clone)]
pub struct FileStore {
    path: PathBuf,
}

/// The records as they are laid out on disk, keyed by identifier.
type Records = BTreeMap<String, BoxInfo>;

impl FileStore {
    /// Read and write box records at `path`.
    ///
    /// The file is created on first write; a missing file reads as an empty
    /// store, so a fresh install needs no initialization step.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// The default location for a user's box records.
    ///
    /// Honors `TINYBOX_STATE_DIR` first so a scripted run can be kept
    /// self-contained, then `XDG_STATE_HOME`, then `~/.local/state`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Store`] when none of those are set, leaving nowhere to
    /// put the file.
    pub fn default_path() -> Result<PathBuf> {
        Self::resolve_path(
            std::env::var_os("TINYBOX_STATE_DIR").as_deref(),
            std::env::var_os("XDG_STATE_HOME").as_deref(),
            std::env::var_os("HOME").as_deref(),
        )
    }

    /// Choose a store path from the three variables that can determine it.
    ///
    /// Split out from [`FileStore::default_path`] because the precedence is the
    /// part worth testing, and mutating process-wide environment variables to
    /// test it would need `unsafe` in Rust 2024 — which this workspace forbids.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Store`] when every argument is `None`.
    fn resolve_path(
        state_dir: Option<&OsStr>,
        xdg_state_home: Option<&OsStr>,
        home: Option<&OsStr>,
    ) -> Result<PathBuf> {
        if let Some(dir) = state_dir {
            return Ok(PathBuf::from(dir).join("boxes.json"));
        }
        if let Some(dir) = xdg_state_home {
            return Ok(PathBuf::from(dir).join("tinybox").join("boxes.json"));
        }
        home.map(|home| {
            PathBuf::from(home)
                .join(".local")
                .join("state")
                .join("tinybox")
                .join("boxes.json")
        })
        .ok_or_else(|| Error::Store {
            operation: "locate",
            message: "set TINYBOX_STATE_DIR, XDG_STATE_HOME, or HOME".to_owned(),
        })
    }

    /// Where this store keeps its records.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Where the lock guarding this store lives.
    ///
    /// A sibling file rather than the store itself: locking the store would
    /// mean opening it for write before knowing whether there is anything to
    /// write, and the lock has to outlive the rename that replaces it.
    fn lock_path(&self) -> PathBuf {
        self.path.with_extension("lock")
    }

    /// Take the exclusive lock for a read-modify-write sequence.
    ///
    /// Blocks until it is available. The alternative — failing immediately —
    /// would turn two people running `tinybox create` at once into an error
    /// rather than a short wait.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Store`] when the lockfile cannot be created or locked.
    fn lock(&self) -> Result<Lock> {
        let path = self.lock_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| Error::Store {
                operation: "create",
                message: error.to_string(),
            })?;
        }

        let file = File::options()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|error| Error::Store {
                operation: "open the lock",
                message: error.to_string(),
            })?;

        rustix::fs::flock(&file, rustix::fs::FlockOperation::LockExclusive).map_err(|error| {
            Error::Store {
                operation: "lock",
                message: error.to_string(),
            }
        })?;
        Ok(Lock { _file: file })
    }

    /// Read the whole document.
    fn read(&self) -> Result<Records> {
        crate::document::read(&self.path, "box store")
    }

    /// Replace the whole document atomically.
    fn write(&self, records: &Records) -> Result<()> {
        crate::document::write(&self.path, records)
    }
}

impl Store for FileStore {
    fn insert(&self, info: &BoxInfo) -> Result<()> {
        // Held until this method returns, covering the read and the write: two
        // processes that both read first would otherwise each write a document
        // missing the other's box.
        let _lock = self.lock()?;
        let mut records = self.read()?;
        if records.contains_key(info.id.as_str()) {
            return Err(Error::DuplicateBox {
                id: info.id.as_str().to_owned(),
            });
        }
        records.insert(info.id.as_str().to_owned(), info.clone());
        self.write(&records)
    }

    fn get(&self, id: &BoxId) -> Result<BoxInfo> {
        self.read()?
            .remove(id.as_str())
            .ok_or_else(|| Error::UnknownBox {
                id: id.as_str().to_owned(),
            })
    }

    fn list(&self) -> Result<Vec<BoxInfo>> {
        Ok(self.read()?.into_values().collect())
    }

    fn set_state(&self, id: &BoxId, state: BoxState) -> Result<()> {
        let _lock = self.lock()?;
        let mut records = self.read()?;
        let info = records
            .get_mut(id.as_str())
            .ok_or_else(|| Error::UnknownBox {
                id: id.as_str().to_owned(),
            })?;
        info.state = state;
        self.write(&records)
    }

    fn remove(&self, id: &BoxId) -> Result<()> {
        let _lock = self.lock()?;
        let mut records = self.read()?;
        if records.remove(id.as_str()).is_none() {
            return Err(Error::UnknownBox {
                id: id.as_str().to_owned(),
            });
        }
        self.write(&records)
    }
}

/// An exclusive advisory lock, released when this is dropped.
///
/// The file handle is the lock: closing it releases, which is also what the
/// kernel does if the process dies holding it.
#[derive(Debug)]
struct Lock {
    _file: File,
}

#[cfg(test)]
mod test;
