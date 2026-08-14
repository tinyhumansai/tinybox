//! Running commands on the machine tinybox is running on.

use async_trait::async_trait;
use tinybox_core::{Error, ExecOutput, ExecRequest, Host, Result};
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
        // Nothing here reads from the terminal, and a child inheriting stdin
        // would block forever on a prompt no one can answer.
        command.stdin(std::process::Stdio::null());
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
        let output = Self::command(request)?
            .output()
            .await
            .map_err(|error| Error::io("spawn", &error))?;

        Ok(ExecOutput::new(
            // A process killed by a signal has no exit code. Report the shell's
            // convention of 128 + signal rather than inventing a success.
            output.status.code().unwrap_or(EXIT_CODE_UNAVAILABLE),
            output.stdout,
            output.stderr,
        ))
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
