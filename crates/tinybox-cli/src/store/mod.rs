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
//! Writes are atomic: the document is written to a temporary file in the same
//! directory and renamed over the target, so a reader sees either the old file
//! or the new one and never a half-written document. Two processes writing at
//! the same moment can still lose one update — last writer wins. Locking is
//! deferred until there is a reason to believe concurrent CLI invocations
//! matter; the failure is a lost record, not a corrupt file.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs;
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

    /// Read the whole document.
    ///
    /// A missing file is an empty store, not an error: that is what makes the
    /// first run work without a setup step.
    fn read(&self) -> Result<Records> {
        let text = match fs::read_to_string(&self.path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Records::new()),
            Err(error) => {
                return Err(Error::Store {
                    operation: "read",
                    message: error.to_string(),
                });
            }
        };

        serde_json::from_str(&text).map_err(|error| Error::Store {
            operation: "parse",
            message: format!("{} is not a valid box store: {error}", self.path.display()),
        })
    }

    /// Replace the whole document atomically.
    ///
    /// Writes a sibling temporary file and renames it over the target, so a
    /// concurrent reader never observes a partial document. The temporary file
    /// must share a directory with the target for the rename to stay within one
    /// filesystem.
    fn write(&self, records: &Records) -> Result<()> {
        let parent = self.path.parent().ok_or_else(|| Error::Store {
            operation: "write",
            message: format!("{} has no parent directory", self.path.display()),
        })?;
        fs::create_dir_all(parent).map_err(|error| Error::Store {
            operation: "create",
            message: error.to_string(),
        })?;

        let text = serde_json::to_string_pretty(records).map_err(|error| Error::Store {
            operation: "encode",
            message: error.to_string(),
        })?;

        let temporary = self.path.with_extension("json.tmp");
        fs::write(&temporary, text).map_err(|error| Error::Store {
            operation: "write",
            message: error.to_string(),
        })?;
        fs::rename(&temporary, &self.path).map_err(|error| Error::Store {
            operation: "rename",
            message: error.to_string(),
        })
    }
}

impl Store for FileStore {
    fn insert(&self, info: &BoxInfo) -> Result<()> {
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
        let mut records = self.read()?;
        if records.remove(id.as_str()).is_none() {
            return Err(Error::UnknownBox {
                id: id.as_str().to_owned(),
            });
        }
        self.write(&records)
    }
}

#[cfg(test)]
mod test;
