//! Where an [`SshHost`](super::SshHost) connects to, and on what terms.

use std::path::PathBuf;

use tinybox_core::{Error, Result};

/// A machine to reach over SSH.
///
/// Built from a destination — `user@machine` or a name from the user's SSH
/// config — plus the few options tinybox needs to override. Everything else is
/// deliberately left to the user's `~/.ssh/config`, which is where jump hosts,
/// key selection, and connection multiplexing already live.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshTarget {
    destination: String,
    port: Option<u16>,
    identity: Option<PathBuf>,
    known_hosts: Option<PathBuf>,
    accept_new_host_key: bool,
}

impl SshTarget {
    /// Reach `destination`, which may be `machine`, `user@machine`, or a name
    /// from the user's SSH config.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidIdentifier`] when `destination` is empty or
    /// begins with `-`, which `ssh` would read as an option rather than a
    /// machine.
    pub fn new(destination: impl Into<String>) -> Result<Self> {
        let destination = destination.into();
        if destination.is_empty() || destination.starts_with('-') {
            return Err(Error::InvalidIdentifier {
                kind: "ssh destination",
                value: destination,
            });
        }
        Ok(Self {
            destination,
            port: None,
            identity: None,
            known_hosts: None,
            accept_new_host_key: false,
        })
    }

    /// Connect on a port other than the configured default.
    #[must_use]
    pub const fn with_port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    /// Authenticate with a specific private key.
    #[must_use]
    pub fn with_identity(mut self, identity: impl Into<PathBuf>) -> Self {
        self.identity = Some(identity.into());
        self
    }

    /// Trust an unknown host key on first connection.
    ///
    /// This weakens authentication: a machine impersonating the target on that
    /// first connection would be trusted from then on. It exists because
    /// throwaway machines — a container in a test, an ephemeral builder — have
    /// no key to have pinned in advance, and the alternative is that connecting
    /// to one is impossible without editing `known_hosts` by hand.
    ///
    /// It is **off** by default and never inferred. Host key checking itself is
    /// never disabled: this accepts a *new* key, it does not ignore a *changed*
    /// one, which is the case that means something is actually wrong.
    #[must_use]
    pub const fn accepting_new_host_key(mut self) -> Self {
        self.accept_new_host_key = true;
        self
    }

    /// Record host keys in `path` instead of the user's `known_hosts`.
    ///
    /// Two reasons to want this. A test suite must not write to a real user's
    /// `known_hosts`, and a throwaway machine that reuses an address gets new
    /// host keys every time it is rebuilt — which
    /// [`accepting_new_host_key`](Self::accepting_new_host_key) correctly
    /// refuses, because from `ssh`'s side that is indistinguishable from an
    /// impersonation. A per-run file scopes that trust to the run.
    #[must_use]
    pub fn with_known_hosts(mut self, path: impl Into<PathBuf>) -> Self {
        self.known_hosts = Some(path.into());
        self
    }

    /// The destination `ssh` is given.
    #[must_use]
    pub fn destination(&self) -> &str {
        &self.destination
    }

    /// The options `ssh` is invoked with.
    ///
    /// `BatchMode=yes` is the important one: without it a missing or rejected
    /// key makes `ssh` prompt, and a prompt in a program nobody is watching is
    /// a hang rather than a failure. Failing immediately is always better.
    pub(super) fn connection_flags(&self) -> Vec<String> {
        let mut flags = vec![
            // Never prompt: fail instead of hanging on a passphrase or password.
            "-o".to_owned(),
            "BatchMode=yes".to_owned(),
            // No pseudo-terminal, so output arrives unmodified and without the
            // carriage returns a tty would insert into a tar stream.
            "-T".to_owned(),
        ];

        if self.accept_new_host_key {
            // Accepts an unknown key; still refuses a changed one.
            flags.push("-o".to_owned());
            flags.push("StrictHostKeyChecking=accept-new".to_owned());
        }
        if let Some(port) = self.port {
            flags.push("-p".to_owned());
            flags.push(port.to_string());
        }
        if let Some(known_hosts) = &self.known_hosts {
            flags.push("-o".to_owned());
            flags.push(format!("UserKnownHostsFile={}", known_hosts.display()));
        }
        if let Some(identity) = &self.identity {
            flags.push("-i".to_owned());
            flags.push(identity.display().to_string());
            // With an explicit key, do not let the agent offer others first and
            // exhaust the server's authentication attempt limit.
            flags.push("-o".to_owned());
            flags.push("IdentitiesOnly=yes".to_owned());
        }
        flags
    }
}
