//! Keeping a jailed command's environment out of every command line.
//!
//! `/proc/<pid>/cmdline` is readable by every process of the same user, so a
//! `--setenv TOKEN value` on the `bwrap`, `systemd-run` or launcher command
//! line hands the value to all of them. The `--setenv` pairs are written,
//! NUL-separated, to a private file (mode 0600 in a fresh 0700 directory) that
//! the launcher opens as descriptor 9 and deletes before anything else runs;
//! `bwrap --args 9` reads them from there. Setting the variables on the
//! launcher's own environment instead would expose them to the host-side
//! programs on the way (the shell, `systemd-run`), and let a value such as
//! `LD_PRELOAD` run code there.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::{self, Read as _};
use std::path::{Path, PathBuf};

/// The descriptor the launcher opens the file on, and `bwrap --args` reads.
pub(super) const ENV_ARGS_FD: &str = "9";

/// A private file holding a jailed command's `--setenv` arguments.
///
/// Removed when dropped, in case the launcher never ran to remove it.
#[derive(Debug)]
pub(super) struct EnvArgsFile {
    path: PathBuf,
}

impl EnvArgsFile {
    /// Writes `env` as `--setenv KEY VALUE` triples into a new private file in
    /// `$XDG_RUNTIME_DIR` (else the temp directory), refusing a directory that
    /// lies under any of `avoid`, since the jailed program could then read it.
    ///
    /// # Errors
    /// `InvalidInput` when a key or value holds a NUL; `PermissionDenied` when
    /// every candidate directory is under `avoid`; otherwise the I/O error.
    pub(super) fn create(env: &BTreeMap<String, String>, avoid: &[&Path]) -> io::Result<Self> {
        let mut contents = Vec::new();
        for (key, value) in env {
            if key.contains('\0') || value.contains('\0') {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "an environment entry holds a NUL",
                ));
            }
            for part in ["--setenv", key.as_str(), value.as_str()] {
                contents.extend_from_slice(part.as_bytes());
                contents.push(0);
            }
        }
        let base = private_base(avoid)?;
        let dir = base.join(format!("tinybox-env-{}", random_hex()?));
        let path = dir.join("env");
        if let Err(error) = write_private(&dir, &path, &contents) {
            let _ = std::fs::remove_file(&path);
            let _ = std::fs::remove_dir(&dir);
            return Err(error);
        }
        Ok(Self { path })
    }

    /// Where the file is; the launcher's first argument.
    #[must_use]
    pub(super) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for EnvArgsFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
        if let Some(dir) = self.path.parent() {
            let _ = std::fs::remove_dir(dir);
        }
    }
}

/// Creates `dir` (0700) and writes `contents` into a new `path` (0600) in it.
#[cfg(unix)]
fn write_private(dir: &Path, path: &Path, contents: &[u8]) -> io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};

    std::fs::DirBuilder::new().mode(0o700).create(dir)?;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?
        .write_all(contents)
}

/// The native jail runs only on Linux; elsewhere there is nothing to launch.
#[cfg(not(unix))]
fn write_private(_dir: &Path, _path: &Path, _contents: &[u8]) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "private environment files need a Unix host",
    ))
}

/// `$XDG_RUNTIME_DIR` when set and outside `avoid`, else the temp directory,
/// canonicalized before the check so a link into a grant is caught.
fn private_base(avoid: &[&Path]) -> io::Result<PathBuf> {
    std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|dir| dir.is_absolute())
        .into_iter()
        .chain(std::iter::once(std::env::temp_dir()))
        .filter_map(|dir| dir.canonicalize().ok())
        .find(|dir| dir.is_dir() && !avoid.iter().any(|grant| dir.starts_with(grant)))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "no private directory outside the jail's grants for its environment",
            )
        })
}

/// 24 hex characters from the kernel's random source.
fn random_hex() -> io::Result<String> {
    let mut random = [0_u8; 12];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut random)?;
    let mut out = String::new();
    for byte in random {
        let _ = write!(out, "{byte:02x}");
    }
    Ok(out)
}

#[cfg(all(test, unix))]
#[path = "env_file_tests.rs"]
mod tests;
