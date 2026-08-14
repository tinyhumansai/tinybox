//! Requests, results, and box state for the provider traits.

use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::identity::BoxId;
use crate::spec::{BoxSpec, Lifecycle};

/// Where a box is in its life.
///
/// Sandboxes drive boxes through these states; core uses them to reject
/// operations that make no sense yet, reporting
/// [`Error::InvalidState`](crate::error::Error::InvalidState).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum BoxState {
    /// Resources are being allocated and the workspace populated.
    Creating,
    /// Fully provisioned and idle; commands can be started.
    Ready,
    /// At least one command is executing.
    Running,
    /// Frozen, retaining memory state, awaiting a resume.
    Paused,
    /// Shut down but still present, with its filesystem intact.
    Stopped,
    /// Snapshotted and released; only its snapshots remain.
    Archived,
    /// Left unusable by an error, retained so the failure can be inspected.
    Failed,
}

impl BoxState {
    /// Whether a command may be started in this state.
    #[must_use]
    pub const fn accepts_commands(self) -> bool {
        matches!(self, Self::Ready | Self::Running)
    }

    /// Whether the box still holds resources that destroying it would release.
    #[must_use]
    pub const fn is_live(self) -> bool {
        !matches!(self, Self::Archived)
    }
}

impl fmt::Display for BoxState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::Creating => "creating",
            Self::Ready => "ready",
            Self::Running => "running",
            Self::Paused => "paused",
            Self::Stopped => "stopped",
            Self::Archived => "archived",
            Self::Failed => "failed",
        };
        formatter.write_str(text)
    }
}

/// A box as the sandbox currently sees it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct BoxInfo {
    /// The box's identifier within its sandbox.
    pub id: BoxId,
    /// Where the box is in its life.
    pub state: BoxState,
    /// The spec the box was created from.
    pub spec: BoxSpec,
    /// When the box was created, if that is known.
    ///
    /// `None` for a box recorded before tinybox tracked time. It has to be
    /// optional rather than defaulted: defaulting to the epoch would make every
    /// pre-existing box look decades old and be destroyed by the first reap,
    /// which is exactly the failure a compatibility default is supposed to
    /// prevent.
    #[serde(default)]
    pub created_at: Option<SystemTime>,
}

impl BoxInfo {
    /// Record a box in a given state, with no creation time.
    #[must_use]
    pub const fn new(id: BoxId, state: BoxState, spec: BoxSpec) -> Self {
        Self {
            id,
            state,
            spec,
            created_at: None,
        }
    }

    /// Record when the box was created.
    #[must_use]
    pub const fn created_at(mut self, at: SystemTime) -> Self {
        self.created_at = Some(at);
        self
    }

    /// When this box stops being wanted, if it ever does.
    ///
    /// Only ephemeral boxes expire, and only once their creation time is known.
    #[must_use]
    pub fn expires_at(&self) -> Option<SystemTime> {
        let Lifecycle::Ephemeral { ttl } = self.spec.lifecycle else {
            return None;
        };
        self.created_at.map(|created| created + ttl)
    }

    /// Whether this box should be destroyed as of `now`.
    ///
    /// A box whose creation time is unknown never expires. Guessing would mean
    /// destroying somebody's work on the strength of a missing field.
    #[must_use]
    pub fn is_expired(&self, now: SystemTime) -> bool {
        self.expires_at().is_some_and(|expiry| now >= expiry)
    }
}

/// One command to run, in a box or directly on a host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ExecRequest {
    /// The program and its arguments, unshelled.
    ///
    /// Passing an argument vector rather than a command line means no backend
    /// has to quote, and no caller can accidentally inject through a filename.
    pub argv: Vec<String>,
    /// The directory to run in, or the box's default when `None`.
    pub cwd: Option<PathBuf>,
    /// Variables layered over the box's own environment.
    pub env: BTreeMap<String, String>,
    /// Bytes to feed the command on standard input.
    ///
    /// `None` means the command gets nothing and sees end-of-file immediately.
    /// That is the default because a command inheriting a terminal would block
    /// forever on a prompt nobody is there to answer.
    ///
    /// Defaulted on read, for the same reason as
    /// [`BoxSpec::ports`](crate::BoxSpec::ports).
    #[serde(default)]
    pub stdin: Option<Vec<u8>>,
}

impl ExecRequest {
    /// Run `argv` with the box's defaults.
    ///
    /// # Panics
    ///
    /// Does not panic. An empty `argv` is accepted here and rejected by the
    /// backend, so that the error names the sandbox that refused it.
    #[must_use]
    pub fn new<I, S>(argv: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            argv: argv.into_iter().map(Into::into).collect(),
            cwd: None,
            env: BTreeMap::new(),
            stdin: None,
        }
    }

    /// Run in `cwd` instead of the box's default directory.
    #[must_use]
    pub fn with_cwd(mut self, cwd: impl Into<PathBuf>) -> Self {
        self.cwd = Some(cwd.into());
        self
    }

    /// Set one environment variable for this command only.
    #[must_use]
    pub fn with_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.insert(key.into(), value.into());
        self
    }

    /// Feed `stdin` to the command.
    ///
    /// This is how a workspace is synced: a tar stream is piped into a command
    /// on the far side rather than staged through a temporary file that would
    /// have to be cleaned up on a machine tinybox may not reach again.
    #[must_use]
    pub fn with_stdin(mut self, stdin: impl Into<Vec<u8>>) -> Self {
        self.stdin = Some(stdin.into());
        self
    }

    /// The program to execute, or `None` when `argv` is empty.
    #[must_use]
    pub fn program(&self) -> Option<&str> {
        self.argv.first().map(String::as_str)
    }
}

/// What a finished command produced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ExecOutput {
    /// The process exit status. A non-zero value is a result, not an error.
    pub exit_code: i32,
    /// Everything written to standard output, unmodified.
    pub stdout: Vec<u8>,
    /// Everything written to standard error, unmodified.
    pub stderr: Vec<u8>,
}

impl ExecOutput {
    /// Record the result of a finished command.
    #[must_use]
    pub const fn new(exit_code: i32, stdout: Vec<u8>, stderr: Vec<u8>) -> Self {
        Self {
            exit_code,
            stdout,
            stderr,
        }
    }

    /// Whether the command exited zero.
    #[must_use]
    pub const fn succeeded(&self) -> bool {
        self.exit_code == 0
    }

    /// Standard output decoded as UTF-8, with invalid sequences replaced.
    ///
    /// Command output is not guaranteed to be valid UTF-8, so this is lossy by
    /// design; use [`ExecOutput::stdout`] directly when the bytes matter.
    #[must_use]
    pub fn stdout_lossy(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.stdout)
    }

    /// Standard error decoded as UTF-8, with invalid sequences replaced.
    #[must_use]
    pub fn stderr_lossy(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.stderr)
    }
}
