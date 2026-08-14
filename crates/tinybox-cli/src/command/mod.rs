//! Argument parsing and command dispatch.

use std::fmt::Write as _;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use tinybox_core::{
    BoxId, BoxInfo, BoxSpec, ExecRequest, HostRef, PassthroughSandbox, Placement, Sandbox,
    SandboxRef, Store, WorkspaceSource, passthrough,
};
use tinybox_host::{LOCAL, LocalHost};

use crate::store::FileStore;

/// Encapsulate a box and run code in it.
#[derive(Debug, Parser)]
#[command(name = "tinybox", version, about, long_about = None)]
pub struct Cli {
    /// Where box records are kept.
    ///
    /// Defaults to `$TINYBOX_STATE_DIR`, `$XDG_STATE_HOME/tinybox`, or
    /// `~/.local/state/tinybox`.
    #[arg(long, global = true, value_name = "PATH")]
    store: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

/// What the caller asked for.
#[derive(Debug, Subcommand)]
enum Command {
    /// Create a box over a local directory.
    Create {
        /// The directory the box's commands run in. Defaults to the working
        /// directory.
        #[arg(long, value_name = "PATH")]
        dir: Option<PathBuf>,
        /// Set an environment variable for every command in the box, as
        /// `KEY=VALUE`. Repeatable.
        #[arg(long = "env", short = 'e', value_name = "KEY=VALUE")]
        env: Vec<String>,
    },
    /// Run a command in an existing box.
    Exec {
        /// Which box to run in.
        id: String,
        /// The command and its arguments.
        #[arg(trailing_var_arg = true, required = true, value_name = "COMMAND")]
        argv: Vec<String>,
    },
    /// List every box.
    #[command(alias = "list")]
    Ls,
    /// Describe one box.
    Inspect {
        /// Which box to describe.
        id: String,
    },
    /// Destroy a box.
    #[command(alias = "remove")]
    Rm {
        /// Which box to destroy.
        id: String,
    },
    /// Create a box, run one command in it, and destroy it.
    ///
    /// The shape agent workloads want: nothing is left behind, even when the
    /// command fails.
    Run {
        /// The directory the command runs in. Defaults to the working
        /// directory.
        #[arg(long, value_name = "PATH")]
        dir: Option<PathBuf>,
        /// Set an environment variable for the command, as `KEY=VALUE`.
        #[arg(long = "env", short = 'e', value_name = "KEY=VALUE")]
        env: Vec<String>,
        /// The command and its arguments.
        #[arg(trailing_var_arg = true, required = true, value_name = "COMMAND")]
        argv: Vec<String>,
    },
}

/// The exit code for a tinybox failure, as opposed to a failure of the command
/// a box was asked to run.
///
/// Distinct from `1` so a caller can tell "your command exited 1" from "tinybox
/// could not run it". `2` is what clap already uses for a usage error.
const EXIT_TINYBOX_ERROR: u8 = 70;

impl Cli {
    /// Run the parsed command, writing output to `out` and errors to `err`.
    ///
    /// Streams are injected rather than assumed so the whole surface is
    /// testable without capturing the process's own stdout.
    ///
    /// # Errors
    ///
    /// Returns a [`tinybox_core::Error`] when the command could not be carried
    /// out. A command that runs inside a box and exits non-zero is **not** an
    /// error here — its status becomes this process's exit code.
    pub async fn dispatch(
        self,
        out: &mut dyn Write,
        err: &mut dyn Write,
    ) -> tinybox_core::Result<u8> {
        let path = match self.store {
            Some(path) => path,
            None => FileStore::default_path()?,
        };
        let store = Arc::new(FileStore::new(path));
        let sandbox = PassthroughSandbox::new(Arc::new(LocalHost::new()), store.clone());

        match self.command {
            Command::Create { dir, env } => {
                let spec = spec(dir, &env)?;
                let info = sandbox.create(&spec).await?;
                write(out, format!("{}\n", info.id).as_bytes())?;
                // The isolation level is in `inspect`, but a reader who never
                // looks should still be told what they just made.
                write(
                    err,
                    format!(
                        "warning: {} boxes are not isolated; commands run with your full privileges\n",
                        passthrough::NAME
                    )
                    .as_bytes(),
                )?;
                Ok(0)
            }
            Command::Exec { id, argv } => {
                let output = sandbox
                    .exec(&BoxId::new(id)?, &ExecRequest::new(argv))
                    .await?;
                write(out, &output.stdout)?;
                write(err, &output.stderr)?;
                Ok(exit_code(output.exit_code))
            }
            Command::Ls => {
                // Listing is the store's business, not the sandbox's: the
                // store is what owns the set of records.
                let mut rendered = String::new();
                for info in store.list()? {
                    // Formatting into a String cannot fail, so the whole
                    // listing is built first and written once. Interleaving
                    // formatting with fallible writes would put an error branch
                    // between every pair of lines.
                    let _ = writeln!(
                        rendered,
                        "{}\t{}\t{}",
                        info.id,
                        info.state,
                        workspace(&info)
                    );
                }
                write(out, rendered.as_bytes())?;
                Ok(0)
            }
            Command::Inspect { id } => {
                let info = sandbox.inspect(&BoxId::new(id)?).await?;
                let caps = sandbox.capabilities();
                let untrusted = if caps.is_suitable_for_untrusted_code() {
                    "safe"
                } else {
                    "UNSAFE — this sandbox confines nothing"
                };

                // Built as one block and written once, so a broken pipe cannot
                // leave half a report on the terminal.
                let mut rendered = String::new();
                let _ = writeln!(rendered, "id:         {}", info.id);
                let _ = writeln!(rendered, "state:      {}", info.state);
                let _ = writeln!(rendered, "workspace:  {}", workspace(&info));
                let _ = writeln!(
                    rendered,
                    "runner:     {} / {}",
                    info.spec.runner.host, info.spec.runner.sandbox
                );
                let _ = writeln!(rendered, "isolation:  {}", caps.isolation);
                let _ = writeln!(rendered, "untrusted:  {untrusted}");
                write(out, rendered.as_bytes())?;
                Ok(0)
            }
            Command::Rm { id } => {
                let id = BoxId::new(id)?;
                sandbox.destroy(&id).await?;
                write(out, format!("{id}\n").as_bytes())?;
                Ok(0)
            }
            Command::Run { dir, env, argv } => {
                let info = sandbox.create(&spec(dir, &env)?).await?;
                let outcome = sandbox.exec(&info.id, &ExecRequest::new(argv)).await;
                // Destroy the box whether or not the command succeeded, so a
                // failing run leaves no record behind.
                let destroyed = sandbox.destroy(&info.id).await;

                let output = outcome?;
                destroyed?;
                write(out, &output.stdout)?;
                write(err, &output.stderr)?;
                Ok(exit_code(output.exit_code))
            }
        }
    }
}

/// Build the spec for a passthrough box over `dir`.
fn spec(dir: Option<PathBuf>, env: &[String]) -> tinybox_core::Result<BoxSpec> {
    let dir = match dir {
        Some(dir) => dir,
        None => std::env::current_dir().map_err(|error| tinybox_core::Error::Store {
            operation: "locate",
            message: format!("could not read the working directory: {error}"),
        })?,
    };

    let placement = Placement::new(HostRef::new(LOCAL)?, SandboxRef::new(passthrough::NAME)?);
    let mut spec = BoxSpec::new(placement, WorkspaceSource::LocalDir(dir));
    for entry in env {
        let (key, value) = entry.split_once('=').ok_or(tinybox_core::Error::Store {
            operation: "parse",
            message: "environment entries must be KEY=VALUE".to_owned(),
        })?;
        spec = spec.with_env(key, value);
    }
    Ok(spec)
}

/// Render a box's workspace directory for display.
fn workspace(info: &BoxInfo) -> String {
    match &info.spec.source {
        WorkspaceSource::LocalDir(path) => path.display().to_string(),
        other => format!("{other:?}"),
    }
}

/// Narrow a process exit status to the byte an exit code can carry.
///
/// A status outside `0..=255` cannot be represented, and reporting `0` for it
/// would turn a failure into a success.
fn exit_code(status: i32) -> u8 {
    u8::try_from(status).unwrap_or(EXIT_TINYBOX_ERROR)
}

/// Write a whole block to a stream, reporting a closed pipe as an error.
///
/// Every command renders its output first and calls this once. Interleaving
/// formatting with fallible writes would put an error branch between every pair
/// of lines and leave half a report on the terminal when a pipe closes.
fn write(stream: &mut dyn Write, bytes: &[u8]) -> tinybox_core::Result<()> {
    stream
        .write_all(bytes)
        .map_err(|error| tinybox_core::Error::io("write", &error))
}

/// Parse `args`, run the command, and return the process exit code.
///
/// Errors are reported to `err` rather than returned, because this is the top
/// of the program and there is nobody left to hand them to.
pub async fn run<I, T>(args: I, out: &mut dyn Write, err: &mut dyn Write) -> u8
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(parse) => {
            // clap renders its own help and usage text, including the exit code
            // convention: 0 for --help and --version, 2 for misuse. It also
            // knows which stream each belongs on — requested help is output,
            // a usage mistake is a diagnostic — and routing both to stderr
            // would make `tinybox --help | less` come back empty.
            let stream: &mut dyn Write = if parse.use_stderr() { err } else { out };
            let _ = write!(stream, "{parse}");
            return u8::try_from(parse.exit_code()).unwrap_or(EXIT_TINYBOX_ERROR);
        }
    };

    match cli.dispatch(out, err).await {
        Ok(code) => code,
        Err(error) => {
            let _ = writeln!(err, "error: {error}");
            EXIT_TINYBOX_ERROR
        }
    }
}

#[cfg(test)]
mod test;
