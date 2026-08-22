//! Running commands on the machine tinybox is running on.

use async_trait::async_trait;
use tinybox_core::{Error, ExecOutput, ExecRequest, Forward, Host, Result};
use tokio::io::AsyncWriteExt as _;
use tokio::process::Command;

/// The name this host registers under.
pub const NAME: &str = "local";

/// A host that spawns child processes on the local machine.
///
/// This is reach, not confinement. A command run here has the launching user's
/// full privileges; pair it with a real sandbox before running anything
/// untrusted.
#[derive(Debug, Default, Clone, Copy)]
pub struct LocalHost;

impl LocalHost {
    /// A host targeting the local machine.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Translate a request into the command to spawn.
    ///
    /// Split out from [`LocalHost::run`] so that argument, environment, and
    /// working-directory handling is testable without spawning anything.
    ///
    /// The child inherits the parent environment with the request's variables
    /// layered on top. Inheriting is what makes `PATH` lookup work at all, and
    /// a sandbox that wants a clean environment is the component responsible
    /// for enforcing it — this host confines nothing by definition.
    ///
    /// # Errors
    ///
    /// Returns [`Error::EmptyCommand`] when the request names no program.
    fn command(request: &ExecRequest) -> Result<Command> {
        let program = request.program().ok_or_else(|| Error::EmptyCommand {
            sandbox: NAME.to_owned(),
        })?;

        let mut command = Command::new(program);
        command.args(&request.argv[1..]);
        command.envs(&request.env);
        if let Some(cwd) = &request.cwd {
            command.current_dir(cwd);
        }
        command.stdin(if request.stdin.is_some() {
            // A payload has to reach the child through a pipe.
            std::process::Stdio::piped()
        } else {
            // Nothing to feed it, and a child inheriting the terminal would
            // block forever on a prompt no one is there to answer.
            std::process::Stdio::null()
        });
        Ok(command)
    }
}

#[async_trait]
impl Host for LocalHost {
    fn name(&self) -> &'static str {
        NAME
    }

    /// Run a command to completion and collect its output.
    ///
    /// Uses `tokio`'s `output()`, which reads both pipes concurrently. Reading
    /// them in sequence would deadlock as soon as a child filled the pipe it
    /// was not being drained on.
    ///
    /// # Errors
    ///
    /// Returns [`Error::EmptyCommand`] when the request names no program, and
    /// [`Error::Io`] when the process cannot be spawned — a missing binary, an
    /// unreadable working directory, a permission failure. A command that runs
    /// and exits non-zero is **not** an error: that status is reported in
    /// [`ExecOutput::exit_code`], because a failing command is a result.
    async fn run(&self, request: &ExecRequest) -> Result<ExecOutput> {
        let mut command = Self::command(request)?;
        let Some(payload) = request.stdin.as_deref() else {
            let output = command
                .output()
                .await
                .map_err(|error| Error::io("spawn", &error))?;
            return Ok(Self::collect(&output));
        };

        // With a payload the child has to be spawned rather than run in one
        // call, so the pipe can be written and then closed. Closing it is not
        // optional: a child reading to end-of-file would otherwise wait forever
        // for input that has already all been sent.
        command.stdout(std::process::Stdio::piped());
        command.stderr(std::process::Stdio::piped());
        let mut child = command
            .spawn()
            .map_err(|error| Error::io("spawn", &error))?;

        if let Some(mut pipe) = child.stdin.take() {
            pipe.write_all(payload)
                .await
                .map_err(|error| Error::io("write to stdin", &error))?;
            // Dropping the handle closes the pipe, signalling end-of-file.
            drop(pipe);
        }

        let output = child
            .wait_with_output()
            .await
            .map_err(|error| Error::io("wait", &error))?;
        Ok(Self::collect(&output))
    }

    /// Hand the address straight back.
    ///
    /// A port published on this machine is already reachable from this
    /// machine, so there is nothing to tunnel and nothing to hold open. The
    /// method exists so that a caller can ask any host for reach without first
    /// asking which kind of host it has — the difference between `local` and
    /// `ssh` should not leak into code that only wants somewhere to connect.
    ///
    /// # Errors
    ///
    /// Never. The signature is fallible because other hosts' forwards are.
    async fn forward(&self, remote: std::net::SocketAddr) -> Result<Forward> {
        Ok(Forward::direct(remote))
    }
}

impl LocalHost {
    /// Turn a finished process into an [`ExecOutput`].
    fn collect(output: &std::process::Output) -> ExecOutput {
        ExecOutput::new(
            // A process killed by a signal has no exit code. Report the shell's
            // convention of 128 + signal rather than inventing a success.
            output.status.code().unwrap_or(EXIT_CODE_UNAVAILABLE),
            output.stdout.clone(),
            output.stderr.clone(),
        )
    }
}

/// Reported when a process ended without an exit code, which on Unix means it
/// was terminated by a signal.
///
/// `128` is the base the shell uses for signal terminations, and it is outside
/// the range a well-behaved program returns, so it cannot be mistaken for
/// success.
const EXIT_CODE_UNAVAILABLE: i32 = 128;

#[cfg(test)]
mod test;
