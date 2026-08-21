//! Argument parsing and command dispatch.

use std::fmt::Write as _;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand, ValueEnum};
use tinybox_core::{
    BoxId, BoxInfo, BoxSpec, Clock, Error, ExecRequest, Host, HostRef, NetworkPolicy,
    PassthroughSandbox, Placement, PortMapping, Sandbox, SandboxRef, SnapshotId, Store,
    SystemClock, TemplateName, Templates, WorkspaceSource, passthrough,
};
use tinybox_docker::DockerSandbox;
use tinybox_host::LocalHost;
use tinybox_linux::NamespaceSandbox;
use tinybox_microvm::MicroVmSandbox;
use tinybox_ssh::{SshHost, SshTarget};
use tinybox_sync::{Exclusions, Syncer};

use crate::store::FileStore;
use crate::templates::FileTemplates;

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

    /// Run on another machine over SSH, as `ssh://user@machine` or a name from
    /// your SSH config.
    #[arg(long, global = true, value_name = "TARGET")]
    host: Option<String>,

    /// Connect on a port other than the configured default.
    #[arg(long, global = true, value_name = "PORT", requires = "host")]
    ssh_port: Option<u16>,

    /// Authenticate with a specific private key.
    #[arg(long, global = true, value_name = "PATH", requires = "host")]
    ssh_identity: Option<PathBuf>,

    /// Record host keys here instead of in `~/.ssh/known_hosts`.
    #[arg(long, global = true, value_name = "PATH", requires = "host")]
    ssh_known_hosts: Option<PathBuf>,

    /// The uncompressed guest kernel a microVM boots.
    ///
    /// Required by `--sandbox microvm`; tinybox does not download one.
    #[arg(long, global = true, value_name = "PATH")]
    microvm_kernel: Option<PathBuf>,

    /// Trust an unknown SSH host key on first connection.
    ///
    /// Weakens authentication and is off by default; a changed key is still
    /// refused either way.
    #[arg(long, global = true, requires = "host")]
    accept_new_host_key: bool,

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
    /// Linux namespaces, rootless and with no daemon. Isolates a directory you
    /// already have, rather than an image.
    Namespace,
    /// A Firecracker microVM with its own kernel. The strongest boundary
    /// available, and the only one a kernel exploit cannot cross.
    Microvm,
}

impl SandboxKind {
    /// The name this kind registers under.
    const fn name(self) -> &'static str {
        match self {
            Self::Passthrough => passthrough::NAME,
            Self::Docker => tinybox_docker::NAME,
            Self::Namespace => tinybox_linux::NAME,
            Self::Microvm => tinybox_microvm::NAME,
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
        /// Start from a saved template, skipping whatever provisioning went
        /// into it.
        #[arg(long, value_name = "NAME", conflicts_with_all = ["dir", "image"])]
        template: Option<String>,
        /// The directory the box's commands run in. Defaults to the working
        /// directory.
        #[arg(long, value_name = "PATH")]
        dir: Option<PathBuf>,
        /// Set an environment variable for every command in the box, as
        /// `KEY=VALUE`. Repeatable.
        #[arg(long = "env", short = 'e', value_name = "KEY=VALUE")]
        env: Vec<String>,
        /// Publish a guest port, as `GUEST` or `HOST:GUEST`. Repeatable.
        #[arg(long = "publish", short = 'p', value_name = "[HOST:]GUEST")]
        publish: Vec<String>,
    },
    /// Send a local directory to the machine a box will run on.
    ///
    /// Reads the workspace's own `.gitignore` and `.boxignore`, so build output
    /// stays behind without anyone listing it. Sends nothing when the far side
    /// already has this exact tree.
    Sync {
        /// The directory to send. Defaults to the working directory.
        #[arg(long, value_name = "PATH")]
        dir: Option<PathBuf>,
        /// Where it lands on the far side.
        #[arg(long, value_name = "PATH")]
        to: String,
        /// Send everything, ignoring `.gitignore` and `.boxignore`.
        #[arg(long)]
        no_ignore: bool,
    },
    /// Save, list, and forget templates.
    ///
    /// A template is a named snapshot, so starting from one skips whatever
    /// provisioning went into it.
    #[command(subcommand)]
    Template(TemplateCommand),
    /// Destroy every box whose lifetime has run out.
    ///
    /// An explicit command rather than a background timer, because tinybox has
    /// no long-running process to hold one. Run it from cron or by hand.
    Reap {
        /// Report what would be destroyed without destroying it.
        #[arg(long)]
        dry_run: bool,
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
    /// Start a command in a box and leave it running.
    ///
    /// Where `exec` waits, this returns a process id as soon as the command is
    /// started. It is how a server gets into a box; `exec` would never return.
    Spawn {
        /// Which box to start it in.
        id: String,
        /// The command and its arguments.
        #[arg(trailing_var_arg = true, required = true, value_name = "COMMAND")]
        argv: Vec<String>,
    },
    /// Report whether a spawned process is still running.
    Ps {
        /// Which box it was started in.
        id: String,
        /// The process id `spawn` printed.
        process: String,
    },
    /// Stop a spawned process.
    ///
    /// Succeeds when it has already exited: stopping something already stopped
    /// is the outcome the caller wanted.
    Kill {
        /// Which box it was started in.
        id: String,
        /// The process id `spawn` printed.
        process: String,
    },
    /// Make a port on the box's machine reachable from this one.
    ///
    /// Publishing a port (`create -p`) puts it on the machine the box runs on.
    /// When that is somewhere else, this is what closes the gap. The tunnel
    /// lasts as long as the command runs, so it holds until interrupted.
    Forward {
        /// The port on the box's machine.
        port: u16,
        /// The address to reach it at over there. Defaults to loopback, which
        /// is where a published port lands.
        #[arg(long, value_name = "IP", default_value = "127.0.0.1")]
        address: std::net::IpAddr,
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
        /// Start from a saved template, skipping whatever provisioning went
        /// into it.
        #[arg(long, value_name = "NAME", conflicts_with_all = ["dir", "image"])]
        template: Option<String>,
        /// The directory the command runs in. Defaults to the working
        /// directory.
        #[arg(long, value_name = "PATH")]
        dir: Option<PathBuf>,
        /// Set an environment variable for the command, as `KEY=VALUE`.
        #[arg(long = "env", short = 'e', value_name = "KEY=VALUE")]
        env: Vec<String>,
        /// Publish a guest port, as `GUEST` or `HOST:GUEST`. Repeatable.
        #[arg(long = "publish", short = 'p', value_name = "[HOST:]GUEST")]
        publish: Vec<String>,
        /// The command and its arguments.
        #[arg(trailing_var_arg = true, required = true, value_name = "COMMAND")]
        argv: Vec<String>,
    },
}

/// What to do with templates.
#[derive(Debug, Subcommand)]
enum TemplateCommand {
    /// Capture a box and remember the snapshot under a name.
    Save {
        /// The name to remember it as.
        name: String,
        /// The box to capture.
        #[arg(long, value_name = "ID")]
        from: String,
    },
    /// List every saved template.
    #[command(alias = "list")]
    Ls,
    /// Forget a template.
    ///
    /// The snapshot it pointed at is left alone; this retires a name.
    #[command(alias = "remove")]
    Rm {
        /// The name to forget.
        name: String,
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
    /// Open the box store and decide where commands run.
    ///
    /// Split out of [`Cli::dispatch`] so that dispatch stays a router: the
    /// preamble is the same for every command and none of it depends on which
    /// one was asked for.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Store`] when no store location can be determined, and
    /// [`Error::InvalidIdentifier`] when the SSH destination is unusable.
    fn resolve(&self, local: Arc<dyn Host>) -> tinybox_core::Result<Context> {
        let path = match &self.store {
            Some(path) => path.clone(),
            None => FileStore::default_path()?,
        };
        // Templates live beside the boxes they were made from, so pointing
        // `--store` elsewhere moves both rather than mixing one directory's
        // boxes with another's names.
        let templates: Arc<dyn Templates> = Arc::new(FileTemplates::beside(&path));
        let store: Arc<dyn Store> = Arc::new(FileStore::new(path));

        // `--host` chooses reach; the sandbox chooses confinement. They are
        // independent, so every backend works remotely without knowing it.
        let reach = reach(
            local,
            self.host.as_deref(),
            &SshOptions {
                port: self.ssh_port,
                identity: self.ssh_identity.clone(),
                known_hosts: self.ssh_known_hosts.clone(),
                accept_new_host_key: self.accept_new_host_key,
            },
        )?;
        Ok(Context {
            store,
            templates,
            reach,
        })
    }

    /// Run the parsed command, writing output to `out` and errors to `err`.
    ///
    /// Streams are injected rather than assumed so the whole surface is
    /// testable without capturing the process's own stdout, and `host` is
    /// injected so the backends that shell out to an external tool are
    /// reachable without that tool being installed.
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
        let Context {
            store,
            templates,
            reach,
        } = self.resolve(host)?;
        let backends = Backends {
            reach: &reach,
            store: &store,
            namespace: self.namespace.as_deref(),
            kernel: self.microvm_kernel.as_deref(),
        };
        let build = |kind: SandboxKind| backends.get(kind);

        match self.command {
            Command::Create {
                sandbox: kind,
                image,
                template,
                dir,
                env,
                publish,
            } => {
                let sandbox = build(kind)?;
                let spec = new_spec(
                    kind, &reach, &templates, template, image, dir, &env, &publish,
                )?;
                announce(&sandbox.create(&spec).await?, sandbox.as_ref(), out, err)
            }
            Command::Exec { id, argv } => {
                let id = BoxId::new(id)?;
                let sandbox = build(sandbox_of(&store, &id)?)?;
                let output = sandbox.exec(&id, &ExecRequest::new(argv)).await?;
                report(&output, out, err)
            }
            Command::Spawn { id, argv } => {
                let id = BoxId::new(id)?;
                let sandbox = build(sandbox_of(&store, &id)?)?;
                let process = sandbox.spawn(&id, &ExecRequest::new(argv)).await?;
                line(out, process.as_ref())
            }
            Command::Ps { id, process } => {
                let id = BoxId::new(id)?;
                let sandbox = build(sandbox_of(&store, &id)?)?;
                let running = sandbox.is_running(&id, &ProcessId::new(process)?).await?;
                // A process that has exited is an answer, not a failure, so it
                // is reported on stdout rather than as a non-zero exit.
                line(out, if running { "running" } else { "gone" })
            }
            Command::Kill { id, process } => {
                let id = BoxId::new(id)?;
                let sandbox = build(sandbox_of(&store, &id)?)?;
                sandbox.stop(&id, &ProcessId::new(process)?).await?;
                line(out, "stopped")
            }
            Command::Forward { port, address } => {
                forward(reach.as_ref(), (address, port).into(), out).await
            }
            // Listing is the store's business, not the sandbox's: the store is
            // what owns the set of records.
            Command::Ls => text(out, &render_listing(&store.list()?)),
            Command::Inspect { id } => {
                let id = BoxId::new(id)?;
                let sandbox = build(sandbox_of(&store, &id)?)?;
                let info = sandbox.inspect(&id).await?;
                text(out, &render_inspect(&info, sandbox.as_ref()))
            }

            Command::Rm { id } => remove(&store, &backends, id, out).await,
            Command::Sync { dir, to, no_ignore } => {
                write(out, sync(reach, dir, &to, no_ignore).await?.as_bytes())?;
                Ok(0)
            }
            Command::Template(command) => {
                write(
                    out,
                    template(&templates, &store, &build, command)
                        .await?
                        .as_bytes(),
                )?;
                Ok(0)
            }
            Command::Reap { dry_run } => {
                let now = SystemClock::new().now();
                text(out, &reap(&store, &build, now, dry_run).await?)
            }
            Command::Snapshot { id } => {
                let id = BoxId::new(id)?;
                let snapshot = build(sandbox_of(&store, &id)?)?.snapshot(&id).await?;
                line(out, snapshot.as_ref())
            }
            Command::Fork {
                snapshot,
                sandbox: kind,
            } => {
                let sandbox = build(kind)?;
                let snapshot = SnapshotId::new(snapshot)?;
                // The snapshot supplies the filesystem, so the spec only has to
                // name where the fork runs.
                let source = WorkspaceSource::Snapshot(snapshot.clone());
                let spec = spec(kind, reach.name(), source, &[], &[])?;
                announce(
                    &sandbox.fork(&snapshot, &spec).await?,
                    sandbox.as_ref(),
                    out,
                    err,
                )
            }
            Command::Run {
                sandbox: kind,
                image,
                template,
                dir,
                env,
                publish,
                argv,
            } => {
                let sandbox = build(kind)?;
                let spec = new_spec(
                    kind, &reach, &templates, template, image, dir, &env, &publish,
                )?;
                let output = run_once(sandbox.as_ref(), &spec, argv).await?;
                report(&output, out, err)
            }
        }
    }
}

/// Resolve where commands run.
///
/// Without `--host` that is the local machine. With it, an [`SshHost`] wrapping
/// the local one — so `ssh` runs here and everything else runs over there.
///
/// # Errors
///
/// Returns [`Error::InvalidIdentifier`] when the destination is empty or would
/// be read by `ssh` as an option rather than a machine.
fn reach(
    local: Arc<dyn Host>,
    destination: Option<&str>,
    options: &SshOptions,
) -> tinybox_core::Result<Arc<dyn Host>> {
    let Some(destination) = destination else {
        return Ok(local);
    };

    // `ssh://` is accepted because it is what people type, but it is not part
    // of what ssh itself understands.
    let destination = destination.strip_prefix("ssh://").unwrap_or(destination);
    let mut target = SshTarget::new(destination)?;

    // Everything not named here is left to the user's `~/.ssh/config`, which is
    // where jump hosts and multiplexing already live. These four exist because
    // a throwaway machine — an ephemeral builder, a container in a test — has
    // no config entry and cannot be given one in advance.
    if let Some(port) = options.port {
        target = target.with_port(port);
    }
    if let Some(identity) = &options.identity {
        target = target.with_identity(identity);
    }
    if let Some(known_hosts) = &options.known_hosts {
        target = target.with_known_hosts(known_hosts);
    }
    if options.accept_new_host_key {
        target = target.accepting_new_host_key();
    }
    Ok(Arc::new(SshHost::new(local, target)))
}

/// What every command needs before it can do anything.
///
/// The three are resolved together because they are decided together: the store
/// location determines where templates live, and `--host` decides reach for all
/// of them.
#[derive(Debug)]
struct Context {
    store: Arc<dyn Store>,
    templates: Arc<dyn Templates>,
    reach: Arc<dyn Host>,
}

/// The SSH settings a caller can override from the command line.
#[derive(Debug, Default)]
struct SshOptions {
    port: Option<u16>,
    identity: Option<PathBuf>,
    known_hosts: Option<PathBuf>,
    accept_new_host_key: bool,
}

/// Parse a `--publish` value.
///
/// # Errors
///
/// Returns [`Error::Store`] describing the expected form when the value is not
/// `GUEST` or `HOST:GUEST` with ports in range.
fn port(value: &str) -> tinybox_core::Result<PortMapping> {
    let malformed = || Error::Store {
        operation: "parse",
        message: format!("{value:?} is not a port; expected GUEST or HOST:GUEST"),
    };

    Ok(match value.split_once(':') {
        None => PortMapping::dynamic(value.parse().map_err(|_| malformed())?),
        Some((host, guest)) => PortMapping::fixed(
            guest.parse().map_err(|_| malformed())?,
            host.parse().map_err(|_| malformed())?,
        ),
    })
}

/// The working directory, or a failure that says why it could not be read.
fn working_directory() -> tinybox_core::Result<PathBuf> {
    std::env::current_dir().map_err(|error| Error::Store {
        operation: "locate",
        message: format!("could not read the working directory: {error}"),
    })
}

/// Build the spec for a box named on the command line.
///
/// Shared by `create` and `run`, which differ only in what happens to the box
/// afterwards.
///
/// # Errors
///
/// Returns whatever resolving the source, the placement, or the ports failed
/// with.
#[expect(
    clippy::too_many_arguments,
    reason = "each argument is one distinct command-line option, and grouping \
              them into a struct would only move the same list somewhere else"
)]
fn new_spec(
    kind: SandboxKind,
    reach: &Arc<dyn Host>,
    templates: &Arc<dyn Templates>,
    template: Option<String>,
    image: Option<String>,
    dir: Option<PathBuf>,
    env: &[String],
    publish: &[String],
) -> tinybox_core::Result<BoxSpec> {
    spec(
        kind,
        reach.name(),
        source(templates, template, image, dir)?,
        env,
        publish,
    )
}

/// Write an already-rendered block and succeed.
///
/// # Errors
///
/// Returns [`Error::Io`] when the stream cannot be written to.
fn text(out: &mut dyn Write, rendered: &str) -> tinybox_core::Result<u8> {
    write(out, rendered.as_bytes())?;
    Ok(0)
}

/// Write one line and succeed.
///
/// # Errors
///
/// Returns [`Error::Io`] when the stream cannot be written to.
fn line(out: &mut dyn Write, value: &str) -> tinybox_core::Result<u8> {
    text(out, &format!("{value}\n"))
}

/// Forward a finished command's output and status to the caller.
///
/// # Errors
///
/// Returns [`Error::Io`] when either stream cannot be written to.
fn report(
    output: &tinybox_core::ExecOutput,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> tinybox_core::Result<u8> {
    write(out, &output.stdout)?;
    write(err, &output.stderr)?;
    Ok(exit_code(output.exit_code))
}

/// Report a newly created box, warning if its sandbox confines nothing.
///
/// # Errors
///
/// Returns [`Error::Io`] when either stream cannot be written to.
fn announce(
    info: &BoxInfo,
    sandbox: &dyn Sandbox,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> tinybox_core::Result<u8> {
    write(out, format!("{}\n", info.id).as_bytes())?;
    warn_if_unconfined(err, sandbox)?;
    Ok(0)
}

/// Create a box, run one command in it, and destroy it.
///
/// # Errors
///
/// Returns whatever creating, running, or destroying failed with. The box is
/// destroyed whether or not the command succeeded, so a failing run leaves no
/// record behind.
async fn run_once(
    sandbox: &dyn Sandbox,
    spec: &BoxSpec,
    argv: Vec<String>,
) -> tinybox_core::Result<tinybox_core::ExecOutput> {
    let info = sandbox.create(spec).await?;
    let outcome = sandbox.exec(&info.id, &ExecRequest::new(argv)).await;
    // Unconditional: a command that failed must not leak the box it ran in.
    let destroyed = sandbox.destroy(&info.id).await;

    let output = outcome?;
    destroyed?;
    Ok(output)
}

/// Resolve where a new box's filesystem comes from.
///
/// A template, an image, or a directory — never more than one, which clap
/// already enforces, because they are three answers to the same question.
///
/// # Errors
///
/// Returns [`Error::UnknownTemplate`] when the named template has never been
/// saved, and [`Error::Store`] when the working directory is needed but
/// unreadable.
fn source(
    templates: &Arc<dyn Templates>,
    template: Option<String>,
    image: Option<String>,
    dir: Option<PathBuf>,
) -> tinybox_core::Result<WorkspaceSource> {
    if let Some(name) = template {
        return Ok(WorkspaceSource::Snapshot(
            templates.get(&TemplateName::new(name)?)?,
        ));
    }
    if let Some(image) = image {
        return Ok(WorkspaceSource::OciImage(image));
    }
    Ok(WorkspaceSource::LocalDir(match dir {
        Some(dir) => dir,
        None => working_directory()?,
    }))
}

/// Save, list, or forget a template.
///
/// # Errors
///
/// Returns whatever the snapshot or the template index failed with.
async fn template<F>(
    templates: &Arc<dyn Templates>,
    store: &Arc<dyn Store>,
    build: &F,
    command: TemplateCommand,
) -> tinybox_core::Result<String>
where
    F: Fn(SandboxKind) -> tinybox_core::Result<Arc<dyn Sandbox>>,
{
    match command {
        TemplateCommand::Save { name, from } => {
            let name = TemplateName::new(name)?;
            let id = BoxId::new(from)?;
            // Capturing and naming in one step: a snapshot nobody named is a
            // digest somebody has to keep track of by hand.
            let snapshot = build(sandbox_of(store, &id)?)?.snapshot(&id).await?;
            templates.save(&name, &snapshot)?;
            Ok(format!("{name}\t{snapshot}\n"))
        }
        TemplateCommand::Ls => {
            let mut rendered = String::new();
            for (name, snapshot) in templates.list()? {
                let _ = writeln!(rendered, "{name}\t{snapshot}");
            }
            Ok(rendered)
        }
        TemplateCommand::Rm { name } => {
            let name = TemplateName::new(name)?;
            templates.remove(&name)?;
            Ok(format!("{name}\n"))
        }
    }
}

/// Destroy every box whose lifetime has run out.
///
/// Reports what it did rather than staying silent, because a command that
/// deletes things should say which ones.
///
/// # Errors
///
/// Returns whatever the store or a sandbox failed with. One box failing to
/// destroy does not stop the rest: a container someone removed by hand should
/// not block reaping everything else.
async fn reap<F>(
    store: &Arc<dyn Store>,
    build: &F,
    now: std::time::SystemTime,
    dry_run: bool,
) -> tinybox_core::Result<String>
where
    F: Fn(SandboxKind) -> tinybox_core::Result<Arc<dyn Sandbox>>,
{
    let mut rendered = String::new();
    for info in store.list()? {
        if !info.is_expired(now) {
            continue;
        }
        if dry_run {
            let _ = writeln!(rendered, "would reap\t{}", info.id);
            continue;
        }

        match build(sandbox_of(store, &info.id)?)?.destroy(&info.id).await {
            Ok(()) => {
                let _ = writeln!(rendered, "reaped\t{}", info.id);
            }
            // Keep going: one unreachable box must not strand every other
            // expired one.
            Err(error) => {
                let _ = writeln!(rendered, "failed\t{}\t{error}", info.id);
            }
        }
    }
    Ok(rendered)
}

/// Send a workspace and report what happened.
///
/// # Errors
///
/// Returns whatever the sync failed with, and [`Error::Store`] when the working
/// directory is needed but unreadable.
async fn sync(
    reach: Arc<dyn Host>,
    dir: Option<PathBuf>,
    to: &str,
    no_ignore: bool,
) -> tinybox_core::Result<String> {
    let source = match dir {
        Some(dir) => dir,
        None => working_directory()?,
    };
    // The workspace's own rules, unless the caller explicitly wants everything.
    let exclude = if no_ignore {
        Exclusions::none()
    } else {
        Exclusions::read(&source)?
    };
    let outcome = Syncer::new(reach)
        .excluding(exclude)
        .sync(&source, to)
        .await?;
    Ok(render_sync(&outcome))
}

/// Render what a sync did.
fn render_sync(outcome: &tinybox_sync::Sync) -> String {
    match outcome {
        tinybox_sync::Sync::Skipped { fingerprint } => {
            format!("unchanged\t{fingerprint}\n")
        }
        tinybox_sync::Sync::Transferred { fingerprint, bytes } => {
            format!("sent\t{fingerprint}\t{bytes} bytes\n")
        }
    }
}

/// Construct the sandbox a command should act through.
///
/// # Errors
///
/// Returns [`Error::InvalidIdentifier`] when a Docker namespace is not a valid
/// identifier.
/// Destroy one box and print its identifier back.
async fn remove(
    store: &Arc<dyn Store>,
    backends: &Backends<'_>,
    id: String,
    out: &mut dyn Write,
) -> tinybox_core::Result<u8> {
    let id = BoxId::new(id)?;
    backends.get(sandbox_of(store, &id)?)?.destroy(&id).await?;
    line(out, id.as_ref())
}

/// Everything a sandbox needs that does not come from the subcommand.
///
/// A struct rather than four arguments threaded through a closure: the closure
/// is called from a dozen arms, and each new backend option would otherwise
/// widen every one of them.
struct Backends<'a> {
    /// The machine the backend reaches.
    reach: &'a Arc<dyn Host>,
    /// Where boxes are recorded.
    store: &'a Arc<dyn Store>,
    /// What keeps one user's containers from colliding with another's.
    namespace: Option<&'a str>,
    /// The guest kernel a microVM boots, if one was named.
    kernel: Option<&'a std::path::Path>,
}

impl Backends<'_> {
    /// Build the named sandbox.
    fn get(&self, kind: SandboxKind) -> tinybox_core::Result<Arc<dyn Sandbox>> {
        build_sandbox(
            kind,
            self.reach.clone(),
            self.store,
            self.namespace,
            self.kernel,
        )
    }
}

fn build_sandbox(
    kind: SandboxKind,
    host: Arc<dyn Host>,
    store: &Arc<dyn Store>,
    namespace: Option<&str>,
    kernel: Option<&std::path::Path>,
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
        // Limits are opt-in on the backend because they need a systemd user
        // session; the CLI asks for them, so a machine without one fails the
        // command rather than quietly running unlimited.
        SandboxKind::Namespace => {
            Arc::new(NamespaceSandbox::new(host, store.clone()).with_cgroup_limits())
        }
        // A kernel is required rather than guessed at: booting somebody's
        // distribution kernel because it happened to be in /boot would be a
        // surprising thing to do on their behalf, and most are compressed in a
        // format Firecracker cannot read anyway.
        SandboxKind::Microvm => {
            let kernel = kernel.ok_or_else(|| Error::Backend {
                sandbox: tinybox_microvm::NAME.to_owned(),
                operation: "find a guest kernel",
                message: "pass --microvm-kernel; tinybox does not download one".to_owned(),
            })?;
            Arc::new(MicroVmSandbox::new(
                host,
                store.clone(),
                tinybox_microvm::GuestImage::with_kernel(kernel),
            ))
        }
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
    if recorded.as_str() == tinybox_linux::NAME {
        return Ok(SandboxKind::Namespace);
    }
    if recorded.as_str() == tinybox_microvm::NAME {
        return Ok(SandboxKind::Microvm);
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
    reach: &str,
    source: WorkspaceSource,
    env: &[String],
    publish: &[String],
) -> tinybox_core::Result<BoxSpec> {
    // The recorded host is where the box actually runs, so `ls` and `inspect`
    // report the truth rather than always claiming the local machine.
    let placement = Placement::new(HostRef::new(reach)?, SandboxRef::new(kind.name())?);
    let mut spec = BoxSpec::new(placement, source);
    for entry in env {
        let (key, value) = entry.split_once('=').ok_or(tinybox_core::Error::Store {
            operation: "parse",
            message: "environment entries must be KEY=VALUE".to_owned(),
        })?;
        spec = spec.with_env(key, value);
    }
    for value in publish {
        spec = spec.with_port(port(value)?);
    }
    // Publishing a port only makes sense with a network, and the default denies
    // one. Opening it here means `--publish` does what it says rather than
    // being silently dropped by the backend.
    if !publish.is_empty() {
        spec = spec.with_network(NetworkPolicy::Egress);
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
