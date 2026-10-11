//! Safe, bounded file handles rooted in a local workspace.

use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Component, Path, PathBuf};

use cap_std::ambient_authority;
use cap_std::fs::{Dir, File, OpenOptions};
use tinybox_core::{Error, Result, WorkspaceFileReader, WorkspaceFileWriter};

const MAX_PATH_BYTES: usize = 4096;

pub(super) fn open_reader(root: &Path, relative: &Path) -> Result<Box<dyn WorkspaceFileReader>> {
    let relative = validate_relative(relative)?;
    let dir = open_root(root)?;
    let file = dir
        .open(&relative)
        .map_err(|error| Error::io("open workspace file", &error))?;
    let metadata = file
        .metadata()
        .map_err(|error| Error::io("inspect workspace file", &error))?;
    if !metadata.is_file() {
        return Err(Error::InvalidFileTransfer {
            reason: "target is not a regular file",
        });
    }
    Ok(Box::new(LocalFileReader {
        file,
        size: metadata.len(),
    }))
}

pub(super) fn begin_writer(
    root: &Path,
    relative: &Path,
    transfer_id: &str,
) -> Result<Box<dyn WorkspaceFileWriter>> {
    let relative = validate_relative(relative)?;
    if transfer_id.is_empty()
        || transfer_id.len() > 128
        || !transfer_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(Error::InvalidIdentifier {
            kind: "file transfer id",
            value: transfer_id.to_owned(),
        });
    }
    let dir = open_root(root)?;
    let parent = parent_or_dot(&relative);
    dir.create_dir_all(parent)
        .map_err(|error| Error::io("create workspace directory", &error))?;
    let name = relative.file_name().ok_or(Error::InvalidWorkspacePath)?;
    let mut temporary_name = std::ffi::OsString::from(".");
    temporary_name.push(name);
    temporary_name.push(format!(".tinybox-{transfer_id}.tmp"));
    let temporary = parent.join(temporary_name);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    let file = dir
        .open_with(&temporary, &options)
        .map_err(|error| Error::io("create staged workspace file", &error))?;
    Ok(Box::new(LocalFileWriter {
        dir,
        temporary,
        destination: relative,
        file: Some(file),
        next_offset: 0,
        finished: false,
    }))
}

fn open_root(root: &Path) -> Result<Dir> {
    Dir::open_ambient_dir(root, ambient_authority())
        .map_err(|error| Error::io("open workspace root", &error))
}

fn validate_relative(path: &Path) -> Result<PathBuf> {
    let text = path.as_os_str().to_string_lossy();
    if text.is_empty() || text.len() > MAX_PATH_BYTES || text.contains('\0') {
        return Err(invalid_path(path));
    }
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => normalized.push(part),
            _ => return Err(invalid_path(path)),
        }
    }
    if normalized.as_os_str().is_empty() {
        return Err(invalid_path(path));
    }
    Ok(normalized)
}

fn invalid_path(_path: &Path) -> Error {
    Error::InvalidWorkspacePath
}

fn parent_or_dot(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

#[derive(Debug)]
struct LocalFileReader {
    file: File,
    size: u64,
}

#[async_trait::async_trait]
impl WorkspaceFileReader for LocalFileReader {
    fn size(&self) -> u64 {
        self.size
    }

    #[expect(clippy::unused_async, reason = "workspace file reader trait is async")]
    async fn read_chunk(&mut self, offset: u64, max_bytes: usize) -> Result<Vec<u8>> {
        if offset >= self.size || max_bytes == 0 {
            return Ok(Vec::new());
        }
        self.file
            .seek(SeekFrom::Start(offset))
            .map_err(|error| Error::io("seek workspace file", &error))?;
        let wanted = max_bytes.min((self.size - offset).min(usize::MAX as u64) as usize);
        let mut bytes = vec![0; wanted];
        let count = self
            .file
            .read(&mut bytes)
            .map_err(|error| Error::io("read workspace file", &error))?;
        bytes.truncate(count);
        Ok(bytes)
    }
}

#[derive(Debug)]
struct LocalFileWriter {
    dir: Dir,
    temporary: PathBuf,
    destination: PathBuf,
    file: Option<File>,
    next_offset: u64,
    finished: bool,
}

#[async_trait::async_trait]
impl WorkspaceFileWriter for LocalFileWriter {
    #[expect(clippy::unused_async, reason = "workspace file writer trait is async")]
    async fn write_chunk(&mut self, offset: u64, bytes: &[u8]) -> Result<u64> {
        if self.finished || offset != self.next_offset || bytes.is_empty() {
            return Err(Error::InvalidFileTransfer {
                reason: "write offset or state is invalid",
            });
        }
        let next_offset = offset.checked_add(bytes.len() as u64).ok_or_else(|| {
            Error::io(
                "write staged workspace file",
                &std::io::Error::from(std::io::ErrorKind::InvalidInput),
            )
        })?;
        let file = self.file.as_mut().ok_or_else(|| {
            Error::io(
                "write staged workspace file",
                &std::io::Error::from(std::io::ErrorKind::BrokenPipe),
            )
        })?;
        file.write_all(bytes)
            .map_err(|error| Error::io("write staged workspace file", &error))?;
        self.next_offset = next_offset;
        Ok(next_offset)
    }

    #[expect(clippy::unused_async, reason = "workspace file writer trait is async")]
    async fn finish(&mut self) -> Result<u64> {
        if self.finished {
            return Ok(self.next_offset);
        }
        if let Some(file) = self.file.as_mut() {
            file.flush()
                .map_err(|error| Error::io("flush staged workspace file", &error))?;
            file.sync_all()
                .map_err(|error| Error::io("sync staged workspace file", &error))?;
        }
        drop(self.file.take());
        self.dir
            .rename(&self.temporary, &self.dir, &self.destination)
            .map_err(|error| Error::io("publish workspace file", &error))?;
        self.finished = true;
        Ok(self.next_offset)
    }

    #[expect(clippy::unused_async, reason = "workspace file writer trait is async")]
    async fn abort(&mut self) -> Result<()> {
        if self.finished {
            return Ok(());
        }
        drop(self.file.take());
        match self.dir.remove_file(&self.temporary) {
            Ok(()) => {
                self.finished = true;
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                self.finished = true;
                Ok(())
            }
            Err(error) => Err(Error::io("remove staged workspace file", &error)),
        }
    }
}

impl Drop for LocalFileWriter {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        drop(self.file.take());
        let _ = self.dir.remove_file(&self.temporary);
    }
}

#[cfg(test)]
#[path = "files_tests.rs"]
mod tests;
