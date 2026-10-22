//! The launcher between the host and `bwrap`.
//!
//! Two things have to happen on the host side of the sandbox that `std` cannot
//! do safely (the workspace forbids `unsafe`):
//!
//! 1. **Keep secrets out of `argv`.** `/proc/<pid>/cmdline` is world-readable,
//!    so `--setenv TOKEN value` on the `bwrap` command line would hand the
//!    caller's credentials to every local user. The whole `bwrap` argument
//!    list is written NUL-separated to a private file (mode 0600 in a fresh
//!    0700 directory) and handed over with `bwrap --args 9`. The launcher
//!    deletes the file as soon as it has it open.
//! 2. **Close inherited descriptors.** Every descriptor above 2 that the host
//!    left without `O_CLOEXEC` would otherwise reach the sandbox. The launcher
//!    enumerates `/proc/self/fd` *after* the fork/exec, in a single-threaded
//!    process, so a descriptor another host thread opens concurrently cannot
//!    slip through a stale snapshot.
//!
//! Both run in one `sh`/`bash` with an empty environment, so nothing the caller
//! set (`LD_PRELOAD`, `BASH_ENV`, exported functions) can run on the host side.

use std::ffi::OsString;
use std::fmt::Write as _;
use std::io::{self, Read as _, Write as _};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::process::Command;

/// The script: open and delete the args file, close every other inherited
/// descriptor above 2, then `exec bwrap --args 9 -- COMMAND...`. `$0` is
/// `bwrap`, `$1` the args file, the rest the command and its arguments (bwrap
/// reads options from the file but the command itself must be on its argv; a
/// command line is visible to every local user anyway, in the sandbox as on
/// any host).
const SCRIPT: &str = r#"f=$1
shift
exec 9<"$f" || exit 126
command -p rm -f -- "$f"
command -p rmdir -- "${f%/*}" 2>/dev/null
[ -d /proc/self/fd ] || exit 126
for fd in /proc/self/fd/*; do
  n=${fd##*/}
  case $n in
    0|1|2|9) ;;
    *) eval "exec $n>&-" || exit 126 ;;
  esac
done
exec "$0" --args 9 -- "$@"
"#;

/// 24 hex characters from the kernel's random source.
///
/// # Errors
/// Returns the error from reading `/dev/urandom`.
pub(super) fn random_hex() -> io::Result<String> {
    let mut random = [0_u8; 12];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut random)?;
    let mut out = String::new();
    for byte in random {
        let _ = write!(out, "{byte:02x}");
    }
    Ok(out)
}

/// The shell for the launcher: `bash` when present, because `dash` (`/bin/sh`
/// on Debian and Ubuntu) cannot close a descriptor above 9 and the script then
/// fails closed.
pub(super) fn pick_shell(exists: impl Fn(&str) -> bool) -> &'static str {
    ["/bin/bash", "/usr/bin/bash"]
        .into_iter()
        .find(|path| exists(path))
        .unwrap_or("/bin/sh")
}

/// Where the args file may live: `$XDG_RUNTIME_DIR` (a private per-user
/// directory) when set, else the temp directory. A candidate that lies under
/// any of the jail's mounts is refused, since the jailed program could then
/// read or replace the file.
///
/// # Errors
/// `PermissionDenied` when no candidate is outside the jail's grants.
pub(super) fn base_dir(
    grants: &[&Path],
    xdg_runtime_dir: Option<PathBuf>,
    temp_dir: PathBuf,
) -> io::Result<PathBuf> {
    xdg_runtime_dir
        .into_iter()
        .chain(std::iter::once(temp_dir))
        .find(|dir| dir.is_dir() && !grants.iter().any(|grant| dir.starts_with(grant)))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "no private directory outside the jail's grants for the bwrap argument file",
            )
        })
}

/// A private file holding the `bwrap` argument list.
#[derive(Debug)]
pub(super) struct ArgsFile {
    dir: PathBuf,
    file: PathBuf,
}

impl ArgsFile {
    /// Writes `argv` NUL-terminated into a fresh private directory under
    /// `base`.
    ///
    /// # Errors
    /// `InvalidInput` if any argument contains a NUL byte (it would end the
    /// argument early and let the rest be read as further `bwrap` options);
    /// otherwise the filesystem error from creating the directory or file.
    pub(super) fn create(argv: &[OsString], base: &Path) -> io::Result<Self> {
        if argv.iter().any(|arg| arg.as_bytes().contains(&0)) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a bwrap argument contains a NUL byte",
            ));
        }
        let dir = base.join(format!("tinybox-bwrap-{}", random_hex()?));
        // `create`, not `create_all`: an existing path is an error, never reused.
        std::fs::DirBuilder::new().mode(0o700).create(&dir)?;
        let file = dir.join("args");
        let written = (|| {
            let mut out = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&file)?;
            for arg in argv {
                out.write_all(arg.as_bytes())?;
                out.write_all(&[0])?;
            }
            out.flush()
        })();
        let this = Self { dir, file };
        if let Err(error) = written {
            this.discard();
            return Err(error);
        }
        Ok(this)
    }

    /// The file's path (an argument of the launcher, not a secret).
    pub(super) fn path(&self) -> &Path {
        &self.file
    }

    /// Removes the file and directory; the launcher normally already has.
    pub(super) fn discard(&self) {
        let _ = std::fs::remove_file(&self.file);
        let _ = std::fs::remove_dir(&self.dir);
    }
}

/// The launcher command: an empty environment, the script, `bwrap`, the file,
/// then the command to run inside the sandbox and its arguments.
pub(super) fn command(
    shell: &str,
    bwrap: &Path,
    args: &ArgsFile,
    program: &std::ffi::OsStr,
    program_args: &[OsString],
) -> Command {
    let mut launcher = Command::new(shell);
    launcher
        .env_clear()
        .arg("-c")
        .arg(SCRIPT)
        .arg(bwrap)
        .arg(args.path())
        .arg(program)
        .args(program_args);
    launcher
}

#[cfg(test)]
#[path = "launcher_tests.rs"]
mod tests;
