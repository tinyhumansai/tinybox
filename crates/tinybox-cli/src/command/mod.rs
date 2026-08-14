//! Argument parsing and command dispatch.

use std::fmt::Write as _;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand, ValueEnum};
use tinybox_core::{
    BoxId, BoxInfo, BoxSpec, Error, ExecRequest, Host, HostRef, PassthroughSandbox, Placement,
    Sandbox, SandboxRef, SnapshotId, Store, WorkspaceSource, passthrough,
};
use tinybox_docker::DockerSandbox;
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

    /// Which Docker namespace to use, keeping containers from separate stores
    /// on one machine apart.
    #[arg(long, global = true, value_name = "NAME")]
    namespace: Option<String>,

    #[command(subcommand)]
    command: Command,
}

/// Which sandbox a new box runs in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum SandboxKind {
    /// No confinement at all: an ordinary process with your full privileges.
    Passthrough,
    /// A Docker container, with its own process table, filesystem, and limits.
    Docker,
}

impl SandboxKind {
    /// The name this kind registers under.
    const fn name(self) -> &'static str {
        match self {
            Self::Passthrough => passthrough::NAME,
            Self::Docker => tinybox_docker::NAME,
        }
    }
}

/// What the caller asked for.
#[derive(Debug, Subcommand)]
enum Command {
    /// Create a box over a local directory.
    Create {
        /// Which sandbox to run in.
        #[arg(long, value_enum, default_value_t = SandboxKind::Passthrough)]
        sandbox: SandboxKind,
        /// Start from an OCI image instead of a directory. Docker only.
        #[arg(long, value_name = "REF", conflicts_with = "dir")]
        image: Option<String>,
        /// The directory the box's commands run in. Defaults to the working
        /// directory.
        #[arg(long, value_name = "PATH")]
        dir: Option<PathBuf>,
        /// Set an environment variable for every command in the box, as
        /// `KEY=VALUE`. Repeatable.
        #[arg(long = "env", short = 'e', value_name = "KEY=VALUE")]
        env: Vec<String>,
    },
    /// Capture a box's filesystem.
    Snapshot {
        /// Which box to capture.
        id: String,
    },
    /// Create a new box from a snapshot.
    Fork {
        /// The snapshot to start from.
        snapshot: String,
        /// Which sandbox to run the fork in.
        #[arg(long, value_enum, default_value_t = SandboxKind::Docker)]
        sandbox: SandboxKind,
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
        /// Which sandbox to run in.
        #[arg(long, value_enum, default_value_t = SandboxKind::Passthrough)]
        sandbox: SandboxKind,
        /// Start from an OCI image instead of a directory. Docker only.
        #[arg(long, value_name = "REF", conflicts_with = "dir")]
        image: Option<String>,
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
        host: Arc<dyn Host>,
        out: &mut dyn Write,
        err: &mut dyn Write,
    ) -> tinybox_core::Result<u8> {
        let path = match self.store {
            Some(path) => path,
            None => FileStore::default_path()?,
        };
        let store: Arc<dyn Store> = Arc::new(FileStore::new(path));
        let namespace = self.namespace;
        let build =
            |kind: SandboxKind| build_sandbox(kind, host.clone(), &store, namespace.as_deref());

        match self.command {
            Command::Create {
                sandbox: kind,
                image,
                dir,
                env,
            } => {
                let sandbox = build(kind)?;
                let info = sandbox.create(&spec(kind, image, dir, &env)?).await?;
                write(out, format!("{}\n", info.id).as_bytes())?;
                warn_if_unconfined(err, sandbox.as_ref())?;
                Ok(0)
            }
            Command::Exec { id, argv } => {
                let id = BoxId::new(id)?;
                let sandbox = build(sandbox_of(&store, &id)?)?;
                let output = sandbox.exec(&id, &ExecRequest::new(argv)).await?;
                write(out, &output.stdout)?;
                write(err, &output.stderr)?;
                Ok(exit_code(output.exit_code))
            }
            Command::Ls => {
                // Listing is the store's business, not the sandbox's: the
                // store is what owns the set of records.
                write(out, render_listing(&store.list()?).as_bytes())?;
                Ok(0)
            }
            Command::Inspect { id } => {
                let id = BoxId::new(id)?;
                let sandbox = build(sandbox_of(&store, &id)?)?;
                let info = sandbox.inspect(&id).await?;
                write(out, render_inspect(&info, sandbox.as_ref()).as_bytes())?;
                Ok(0)
            }
            Command::Rm { id } => {
                let id = BoxId::new(id)?;
                let sandbox = build(sandbox_of(&store, &id)?)?;
                sandbox.destroy(&id).await?;
                write(out, format!("{id}\n").as_bytes())?;
                Ok(0)
            }
            Command::Snapshot { id } => {
                let id = BoxId::new(id)?;
                let sandbox = build(sandbox_of(&store, &id)?)?;
                let snapshot = sandbox.snapshot(&id).await?;
                write(out, format!("{snapshot}\n").as_bytes())?;
                Ok(0)
            }
            Command::Fork {
                snapshot,
                sandbox: kind,
            } => {
                let sandbox = build(kind)?;
                let snapshot = SnapshotId::new(snapshot)?;
                // The snapshot supplies the filesystem, so the spec only has to
                // name where the fork runs.
                let spec = spec(kind, None, Some(PathBuf::from(".")), &[])?
                    .with_source(WorkspaceSource::Snapshot(snapshot.clone()));
                let info = sandbox.fork(&snapshot, &spec).await?;
                write(out, format!("{}\n", info.id).as_bytes())?;
                warn_if_unconfined(err, sandbox.as_ref())?;
                Ok(0)
            }
            Command::Run {
                sandbox: kind,
                image,
                dir,
                env,
                argv,
            } => {
                let sandbox = build(kind)?;
                let info = sandbox.create(&spec(kind, image, dir, &env)?).await?;
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

/// Construct the sandbox a command should act through.
///
/// # Errors
///
/// Returns [`Error::InvalidIdentifier`] when a Docker namespace is not a valid
/// identifier.
fn build_sandbox(
    kind: SandboxKind,
    host: Arc<dyn Host>,
    store: &Arc<dyn Store>,
    namespace: Option<&str>,
) -> tinybox_core::Result<Arc<dyn Sandbox>> {
    Ok(match kind {
        SandboxKind::Passthrough => Arc::new(PassthroughSandbox::new(host, store.clone())),
        SandboxKind::Docker => match namespace {
            Some(namespace) => Arc::new(DockerSandbox::with_namespace(
                host,
                store.clone(),
                namespace,
            )?),
            None => Arc::new(DockerSandbox::new(host, store.clone())),
        },
    })
}

/// Which sandbox an existing box belongs to.
///
/// Read from the record rather than taken from a flag: a box created under
/// Docker must be executed in and destroyed through Docker, and asking the
/// caller to remember that is how containers get orphaned.
///
/// # Errors
///
/// Returns [`Error::UnknownBox`] when `id` does not resolve, and
/// [`Error::Unsupported`] when the record names a sandbox this build cannot
/// construct.
fn sandbox_of(store: &Arc<dyn Store>, id: &BoxId) -> tinybox_core::Result<SandboxKind> {
    let recorded = store.get(id)?.spec.workspace.sandbox;
    if recorded.as_str() == tinybox_docker::NAME {
        return Ok(SandboxKind::Docker);
    }
    if recorded.as_str() == passthrough::NAME {
        return Ok(SandboxKind::Passthrough);
    }
    Err(Error::Unsupported {
        sandbox: recorded.into_string(),
        capability: tinybox_core::Capability::Fork,
    })
}

/// Tell the caller when the box they just made confines nothing.
///
/// The isolation level is in `inspect`, but a reader who never looks should
/// still be told.
fn warn_if_unconfined(err: &mut dyn Write, sandbox: &dyn Sandbox) -> tinybox_core::Result<()> {
    if sandbox.capabilities().is_suitable_for_untrusted_code() {
        return Ok(());
    }
    write(
        err,
        format!(
            "warning: {} boxes are not isolated; commands run with your full privileges\n",
            sandbox.name()
        )
        .as_bytes(),
    )
}

/// Build the spec for a new box.
///
/// An image and a directory are alternatives: an image *is* the filesystem,
/// while a directory is mounted into one.
fn spec(
    kind: SandboxKind,
    image: Option<String>,
    dir: Option<PathBuf>,
    env: &[String],
) -> tinybox_core::Result<BoxSpec> {
    let source = match image {
        Some(image) => WorkspaceSource::OciImage(image),
        None => WorkspaceSource::LocalDir(match dir {
            Some(dir) => dir,
            None => std::env::current_dir().map_err(|error| tinybox_core::Error::Store {
                operation: "locate",
                message: format!("could not read the working directory: {error}"),
            })?,
        }),
    };

    let placement = Placement::new(HostRef::new(LOCAL)?, SandboxRef::new(kind.name())?);
    let mut spec = BoxSpec::new(placement, source);
    for entry in env {
        let (key, value) = entry.split_once('=').ok_or(tinybox_core::Error::Store {
            operation: "parse",
            message: "environment entries must be KEY=VALUE".to_owned(),
        })?;
        spec = spec.with_env(key, value);
    }
    Ok(spec)
}

/// Render the `ls` table.
///
/// Formatting into a `String` cannot fail, so the whole listing is built before
/// anything is written. Interleaving formatting with fallible writes would put
/// an error branch between every pair of lines.
fn render_listing(boxes: &[BoxInfo]) -> String {
    let mut rendered = String::new();
    for info in boxes {
        let _ = writeln!(
            rendered,
            "{}\t{}\t{}\t{}",
            info.id,
            info.spec.workspace.sandbox,
            info.state,
            workspace(info)
        );
    }
    rendered
}

/// Render the `inspect` report.
///
/// Built as one block so a broken pipe cannot leave half a report on the
/// terminal, and so the whole thing is assertable without a stream.
fn render_inspect(info: &BoxInfo, sandbox: &dyn Sandbox) -> String {
    let caps = sandbox.capabilities();
    let untrusted = if caps.is_suitable_for_untrusted_code() {
        "safe"
    } else {
        "UNSAFE — this sandbox confines nothing"
    };
    let declared = caps
        .declared()
        .into_iter()
        .map(|capability| capability.to_string())
        .collect::<Vec<_>>();
    let supports = if declared.is_empty() {
        "nothing beyond running commands".to_owned()
    } else {
        declared.join(", ")
    };

    let mut rendered = String::new();
    let _ = writeln!(rendered, "id:         {}", info.id);
    let _ = writeln!(rendered, "sandbox:    {}", sandbox.name());
    let _ = writeln!(rendered, "state:      {}", info.state);
    let _ = writeln!(rendered, "workspace:  {}", workspace(info));
    let _ = writeln!(
        rendered,
        "runner:     {} / {}",
        info.spec.runner.host, info.spec.runner.sandbox
    );
    let _ = writeln!(rendered, "isolation:  {}", caps.isolation);
    let _ = writeln!(rendered, "untrusted:  {untrusted}");
    let _ = writeln!(rendered, "supports:   {supports}");
    rendered
}

/// Render a box's workspace source for display.
///
/// Each variant gets a form a reader recognizes rather than a `Debug` dump,
/// because this is the column someone scans to find the box they meant.
fn workspace(info: &BoxInfo) -> String {
    match &info.spec.source {
        WorkspaceSource::LocalDir(path) => path.display().to_string(),
        WorkspaceSource::OciImage(reference) => reference.clone(),
        WorkspaceSource::Snapshot(snapshot) => snapshot.to_string(),
        WorkspaceSource::GitRepo { url, rev } => format!("{url}#{rev}"),
        // `WorkspaceSource` is non-exhaustive, so a source added later lands
        // here rather than being omitted from the column entirely.
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
    run_with_host(args, Arc::new(LocalHost::new()), out, err).await
}

/// Parse `args` and run the command against an explicit host.
///
/// [`run`] is this with [`LocalHost`]. The host is injectable so that the whole
/// command surface — including the backends that shell out to an external tool
/// — can be driven without the tool being installed, which is the same
/// separation that keeps `tinybox-docker` testable without a daemon.
///
/// Errors are reported to `err` rather than returned, because this is the top
/// of the program and there is nobody left to hand them to.
pub async fn run_with_host<I, T>(
    args: I,
    host: Arc<dyn Host>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> u8
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

    match cli.dispatch(host, out, err).await {
        Ok(code) => code,
        Err(error) => {
            let _ = writeln!(err, "error: {error}");
            EXIT_TINYBOX_ERROR
        }
    }
}

#[cfg(test)]
mod test;
