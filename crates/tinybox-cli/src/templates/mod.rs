//! Templates that survive the process that saved them.
//!
//! Kept in their own file rather than added to the box document. Extending that
//! document would change its shape, and a store written by an earlier build
//! would stop loading — orphaning every box in it. A second file needs no
//! migration and cannot break the first.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use tinybox_core::{Error, Result, SnapshotId, TemplateName, Templates};

/// Templates recorded as a JSON file on disk.
#[derive(Debug, Clone)]
pub struct FileTemplates {
    path: PathBuf,
}

/// The records as they are laid out on disk, keyed by template name.
type Records = BTreeMap<String, SnapshotId>;

impl FileTemplates {
    /// Read and write templates at `path`.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// The template file that sits beside a box store.
    ///
    /// Derived from the store's location so the two travel together: a user
    /// pointing `--store` somewhere else gets that directory's templates too,
    /// rather than silently mixing one directory's boxes with another's names.
    #[must_use]
    pub fn beside(store: &Path) -> Self {
        Self::new(store.with_file_name("templates.json"))
    }

    /// Where this index keeps its records.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Read the whole document; a missing file is an empty index.
    fn read(&self) -> Result<Records> {
        crate::document::read(&self.path, "template index")
    }

    /// Replace the whole document atomically.
    fn write(&self, records: &Records) -> Result<()> {
        crate::document::write(&self.path, records)
    }
}

impl Templates for FileTemplates {
    fn save(&self, name: &TemplateName, snapshot: &SnapshotId) -> Result<()> {
        let mut records = self.read()?;
        records.insert(name.as_str().to_owned(), snapshot.clone());
        self.write(&records)
    }

    fn get(&self, name: &TemplateName) -> Result<SnapshotId> {
        self.read()?
            .remove(name.as_str())
            .ok_or_else(|| Error::UnknownTemplate {
                name: name.as_str().to_owned(),
            })
    }

    fn list(&self) -> Result<Vec<(TemplateName, SnapshotId)>> {
        self.read()?
            .into_iter()
            .map(|(name, snapshot)| Ok((TemplateName::new(name)?, snapshot)))
            .collect()
    }

    fn remove(&self, name: &TemplateName) -> Result<()> {
        let mut records = self.read()?;
        if records.remove(name.as_str()).is_none() {
            return Err(Error::UnknownTemplate {
                name: name.as_str().to_owned(),
            });
        }
        self.write(&records)
    }
}

#[cfg(test)]
mod test;
