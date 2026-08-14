//! Moving a workspace to the machine that will run it.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use tinybox_core::{Error, ExecRequest, Host, Result};

use crate::exclude::Exclusions;
use crate::fingerprint::Fingerprint;

mod archive;

/// The file a synced workspace carries its fingerprint in.
///
/// It lives with the workspace, on the far side, rather than in local
/// bookkeeping. Local bookkeeping goes stale the moment the remote machine is
/// rebuilt or the directory is deleted, and a stale record causes the one
/// failure that matters here: a skipped transfer that should have happened.
pub const MARKER: &str = ".tinybox-fingerprint";

/// What a sync did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sync {
    /// The far side already had this exact tree, so nothing was sent.
    Skipped {
        /// The fingerprint both sides agree on.
        fingerprint: Fingerprint,
    },
    /// The tree was packed and sent.
    Transferred {
        /// The fingerprint now recorded on the far side.
        fingerprint: Fingerprint,
        /// How many bytes of archive crossed.
        bytes: usize,
    },
}

impl Sync {
    /// Whether anything was actually sent.
    #[must_use]
    pub const fn transferred(&self) -> bool {
        matches!(self, Self::Transferred { .. })
    }

    /// The fingerprint the far side now holds.
    #[must_use]
    pub const fn fingerprint(&self) -> &Fingerprint {
        match self {
            Self::Skipped { fingerprint } | Self::Transferred { fingerprint, .. } => fingerprint,
        }
    }
}

/// Sends a local directory to a destination on some host.
///
/// The archive is built in this process and piped to `tar` on the far side, so
/// the only thing that has to exist over there is `tar` itself — not rsync, and
/// not a tinybox agent. That matters because the far side is frequently a
/// container image someone else built.
#[derive(Debug, Clone)]
pub struct Syncer {
    host: Arc<dyn Host>,
    exclude: Exclusions,
}

impl Syncer {
    /// Send workspaces to `host`.
    #[must_use]
    pub fn new(host: Arc<dyn Host>) -> Self {
        Self {
            host,
            exclude: Exclusions::none(),
        }
    }

    /// Leave behind whatever `exclude` covers.
    ///
    /// Nothing is excluded by default, so sending everything stays an explicit
    /// choice. [`Exclusions::read`] builds this from a workspace's own
    /// `.gitignore` and `.boxignore`.
    #[must_use]
    pub fn excluding(mut self, exclude: Exclusions) -> Self {
        self.exclude = exclude;
        self
    }

    /// What this syncer leaves behind.
    #[must_use]
    pub const fn excluded(&self) -> &Exclusions {
        &self.exclude
    }

    /// Make `destination` on the host match the local directory `source`.
    ///
    /// Returns without sending anything when the far side already reports this
    /// fingerprint, which is the case that makes an edit-run loop cheap.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] when `source` cannot be read or packed, and
    /// [`Error::Backend`] when the far side cannot create the destination or
    /// unpack the archive.
    pub async fn sync(&self, source: impl AsRef<Path>, destination: &str) -> Result<Sync> {
        let source = source.as_ref();
        let fingerprint = Fingerprint::of_directory(source, &self.exclude)?;

        if self.remote_fingerprint(destination).await? == Some(fingerprint.clone()) {
            return Ok(Sync::Skipped { fingerprint });
        }

        let archive = archive::pack(source, &self.exclude, &fingerprint)?;
        let bytes = archive.len();
        self.unpack(destination, archive).await?;

        Ok(Sync::Transferred { fingerprint, bytes })
    }

    /// What the far side says it already has, if anything.
    ///
    /// A missing or unreadable marker reads as "nothing", which makes an
    /// unrecognizable state cause a resend rather than a wrongly skipped one.
    async fn remote_fingerprint(&self, destination: &str) -> Result<Option<Fingerprint>> {
        let marker = format!("{destination}/{MARKER}");
        let output = self.host.run(&ExecRequest::new(["cat", &marker])).await?;

        if !output.succeeded() {
            return Ok(None);
        }
        Ok(Fingerprint::parse(&output.stdout_lossy()).ok())
    }

    /// Create the destination and unpack the archive into it.
    async fn unpack(&self, destination: &str, archive: Vec<u8>) -> Result<()> {
        // `tar` will not create the destination itself, and a missing directory
        // is the normal case on a fresh machine.
        let prepared = self
            .host
            .run(&ExecRequest::new(["mkdir", "-p", destination]))
            .await?;
        if !prepared.succeeded() {
            return Err(Error::Backend {
                sandbox: "sync".to_owned(),
                operation: "create the destination directory",
                message: prepared.stderr_lossy().trim().to_owned(),
            });
        }

        let unpacked = self
            .host
            .run(&ExecRequest::new(["tar", "-xf", "-", "-C", destination]).with_stdin(archive))
            .await?;
        if !unpacked.succeeded() {
            return Err(Error::Backend {
                sandbox: "sync".to_owned(),
                operation: "unpack the workspace",
                message: unpacked.stderr_lossy().trim().to_owned(),
            });
        }
        Ok(())
    }
}

/// Where a workspace lands on the far side by default.
///
/// Under the user's home rather than `/tmp`, because a workspace that vanishes
/// on reboot is a surprising thing to hand someone.
#[must_use]
pub fn default_destination(name: &str) -> PathBuf {
    PathBuf::from("~/.tinybox/workspaces").join(name)
}

#[cfg(test)]
mod test;
