//! Reaching another machine over SSH.

use std::sync::Arc;

use async_trait::async_trait;
use tinybox_core::{Error, ExecOutput, ExecRequest, Host, Result};

mod target;

pub use target::SshTarget;

/// The name this host registers under.
pub const NAME: &str = "ssh";

/// A host that runs commands on another machine.
///
/// # It wraps an inner host rather than speaking SSH itself
///
/// `SshHost` builds an `ssh` command line and hands it to an inner
/// [`Host`] — normally `LocalHost`. That inherits the user's existing SSH
/// configuration, keys, agent, jump hosts, and connection multiplexing, none of
/// which an embedded SSH client would get for free.
///
/// It also composes: an `SshHost` whose inner host is another `SshHost` reaches
/// through a jump box, with no code that knows what a jump box is.
///
/// # What it does not do
///
/// This is reach, not confinement. A command run here has the remote user's
/// full privileges; pair it with a real sandbox before running anything
/// untrusted. Pairing it with [`DockerSandbox`] is what makes Docker run on the
/// far machine, and that needed no Docker-side code — see ADR 0004.
///
/// [`DockerSandbox`]: https://docs.rs/tinybox-docker
#[derive(Debug, Clone)]
pub struct SshHost {
    inner: Arc<dyn Host>,
    target: SshTarget,
}

impl SshHost {
    /// Reach `target` by running `ssh` on `inner`.
    #[must_use]
    pub fn new(inner: Arc<dyn Host>, target: SshTarget) -> Self {
        Self { inner, target }
    }

    /// Where this host connects to.
    #[must_use]
    pub const fn target(&self) -> &SshTarget {
        &self.target
    }

    /// The `ssh` command line for `request`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::EmptyCommand`] when the request names no program.
    fn command(&self, request: &ExecRequest) -> Result<Vec<String>> {
        if request.argv.is_empty() {
            return Err(Error::EmptyCommand {
                sandbox: NAME.to_owned(),
            });
        }

        let mut argv = vec!["ssh".to_owned()];
        argv.extend(self.target.connection_flags());
        argv.push(self.target.destination().to_owned());
        // `--` separates ssh's own options from the remote command, so a
        // command starting with a dash cannot be read as an ssh flag.
        argv.push("--".to_owned());
        argv.push(tinybox_core::shell::script(
            &request.argv,
            request.cwd.as_deref(),
            &request.env,
        ));
        Ok(argv)
    }
}

#[async_trait]
impl Host for SshHost {
    fn name(&self) -> &'static str {
        NAME
    }

    /// Run a command on the far machine and collect its output.
    ///
    /// # Errors
    ///
    /// Returns [`Error::EmptyCommand`] when the request names no program, and
    /// whatever the inner host returns when `ssh` itself cannot be started.
    ///
    /// A command that runs remotely and exits non-zero is **not** an error: its
    /// status is reported in [`ExecOutput::exit_code`], because a failing
    /// command is a result.
    ///
    /// # Ambiguity worth knowing about
    ///
    /// `ssh` exits `255` when *it* fails — an unreachable host, a rejected key
    /// — and otherwise passes the remote command's status through. A remote
    /// command that genuinely exits `255` is therefore indistinguishable from a
    /// connection failure. That is a property of the protocol, not of this
    /// implementation, and it is why connection problems are surfaced from
    /// stderr rather than inferred from the code alone.
    async fn run(&self, request: &ExecRequest) -> Result<ExecOutput> {
        let mut forwarded = ExecRequest::new(self.command(request)?);
        // The payload belongs to the remote command, so it is passed straight
        // through to `ssh`, which forwards its own stdin to the far side.
        if let Some(stdin) = &request.stdin {
            forwarded = forwarded.with_stdin(stdin.clone());
        }
        self.inner.run(&forwarded).await
    }
}

#[cfg(test)]
mod test;
