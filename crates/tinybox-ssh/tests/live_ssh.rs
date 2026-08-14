//! Tests that drive a real `sshd`.
//!
//! Gated behind `TINYBOX_LIVE_SSH=1` and named `live_*` so an ordinary
//! `cargo test` skips them. There is normally no `sshd` to talk to, so the
//! suite starts one in a container with a generated key and connects to it on a
//! forwarded port. That needs a Docker daemon as well.
//!
//! # What only a real server can answer
//!
//! Quoting. `src/host/quote/test.rs` pins what the encoding *should* be, and a
//! property test there round-trips it through a local `sh`. This file proves
//! the same strings survive the whole path — a real SSH connection, a real
//! remote login shell — which is the assertion that matters, because a quoting
//! bug here is a command-injection bug.
//!
//! # Leftovers
//!
//! The server container outlives the run. Test order is not guaranteed, so a
//! cleanup test would be a race against the tests still using it — and did
//! exactly that when this suite first had one. Instead the container name is
//! fixed and every run removes a leftover before starting, which makes a
//! crashed run self-heal on the next one. Remove it by hand with
//! `docker rm -f tinybox-live-sshd`.
//!
//! Run with:
//!
//! ```sh
//! TINYBOX_LIVE_SSH=1 cargo test -p tinybox-ssh --test live_ssh
//! ```

use std::path::PathBuf;
use std::sync::Arc;

use tempfile::TempDir;
use tinybox_core::{Error, ExecRequest, Host, Result};
use tinybox_host::LocalHost;
use tinybox_ssh::{SshHost, SshTarget};

/// The port the containerized server is published on.
///
/// Fixed rather than dynamic so a leaked container is easy to find and remove
/// by hand.
const PORT: u16 = 22022;

/// The container the server runs in.
const CONTAINER: &str = "tinybox-live-sshd";

/// Whether the live suite should run at all.
fn enabled() -> bool {
    std::env::var_os("TINYBOX_LIVE_SSH").is_some()
}

/// One server shared by the whole suite.
///
/// Started once rather than per test, for two reasons. Installing a package and
/// generating host keys takes seconds, and — more importantly — a fresh
/// container on the same port presents *new* host keys, which
/// `accepting_new_host_key` correctly refuses as indistinguishable from an
/// impersonation. One server means one host key for the run.
static SERVER: tokio::sync::OnceCell<Server> = tokio::sync::OnceCell::const_new();

/// The shared server, started on first use.
async fn server() -> Result<&'static Server> {
    SERVER.get_or_try_init(Server::start).await
}

/// A running `sshd`, and the key that reaches it.
struct Server {
    /// Holds the generated key and `known_hosts` alive for the whole run.
    _keys: TempDir,
    identity: PathBuf,
    known_hosts: PathBuf,
}

impl Server {
    /// Start a container running `sshd`, trusting a freshly generated key.
    ///
    /// Everything is thrown away with the container: the key is generated per
    /// run and never leaves the temporary directory, so nothing here can
    /// authorize access to anything real.
    async fn start() -> Result<Self> {
        let local = LocalHost::new();
        let keys = TempDir::new().map_err(|error| Error::io("tempdir", &error))?;
        let identity = keys.path().join("id_ed25519");
        // Never the real one: this suite must not write to a user's known_hosts.
        let known_hosts = keys.path().join("known_hosts");

        run(
            &local,
            &[
                "ssh-keygen",
                "-t",
                "ed25519",
                "-N",
                "",
                "-q",
                "-f",
                &identity.display().to_string(),
            ],
        )
        .await?;
        let public = std::fs::read_to_string(identity.with_extension("pub").as_path())
            .map_err(|error| Error::io("read the generated key", &error))?;

        // Any leftover from an interrupted run would hold the port.
        let _ = local
            .run(&ExecRequest::new(["docker", "rm", "-f", CONTAINER]))
            .await;

        run(
            &local,
            &[
                "docker",
                "run",
                "--detach",
                "--name",
                CONTAINER,
                "--publish",
                &format!("127.0.0.1:{PORT}:22"),
                "alpine:3",
                "sh",
                "-c",
                // A single-user server that exists for the length of this suite:
                // key-only, root login, host keys generated on the spot.
                &format!(
                    "apk add --no-cache openssh >/dev/null && \
                     ssh-keygen -A && \
                     mkdir -p /root/.ssh && \
                     printf '%s' '{}' > /root/.ssh/authorized_keys && \
                     chmod 700 /root/.ssh && chmod 600 /root/.ssh/authorized_keys && \
                     /usr/sbin/sshd -D -e -o PermitRootLogin=prohibit-password",
                    public.trim()
                ),
            ],
        )
        .await?;

        let server = Self {
            _keys: keys,
            identity,
            known_hosts,
        };
        server.wait_until_reachable().await?;
        Ok(server)
    }

    /// Poll until the server answers, or give up.
    ///
    /// Installing a package and generating host keys takes a few seconds, and
    /// the alternative to polling is a fixed sleep that is either too short on
    /// a slow machine or wasted time on a fast one.
    async fn wait_until_reachable(&self) -> Result<()> {
        let probe = self.host()?;
        for _ in 0..60 {
            if probe.run(&ExecRequest::new(["true"])).await?.succeeded() {
                return Ok(());
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
        Err(Error::Backend {
            sandbox: "live-ssh".to_owned(),
            operation: "start a test sshd",
            message: format!("no answer on port {PORT} after 30s"),
        })
    }

    /// An SSH host pointing at this server.
    fn host(&self) -> Result<SshHost> {
        Ok(SshHost::new(Arc::new(LocalHost::new()), self.target()?))
    }

    /// How to reach this server.
    fn target(&self) -> Result<SshTarget> {
        Ok(SshTarget::new("root@127.0.0.1")?
            .with_port(PORT)
            .with_identity(&self.identity)
            .with_known_hosts(&self.known_hosts)
            // The container is new every run, so its host key has never been
            // seen before and could not have been pinned in advance.
            .accepting_new_host_key())
    }
}

/// Run a command locally, failing loudly if it does not succeed.
async fn run(local: &LocalHost, argv: &[&str]) -> Result<String> {
    let output = local.run(&ExecRequest::new(argv.to_vec())).await?;
    if !output.succeeded() {
        return Err(Error::Backend {
            sandbox: "live-ssh".to_owned(),
            operation: "prepare the test server",
            message: output.stderr_lossy().trim().to_owned(),
        });
    }
    Ok(output.stdout_lossy().trim().to_owned())
}

#[tokio::test]
async fn live_a_command_runs_on_the_far_machine() -> Result<()> {
    if !enabled() {
        return Ok(());
    }
    let local = LocalHost::new();
    let remote = server().await?.host()?;

    let output = remote.run(&ExecRequest::new(["hostname"])).await?;

    assert!(output.succeeded(), "{}", output.stderr_lossy());
    // The container's hostname is its own id, not this machine's.
    assert_ne!(
        output.stdout_lossy().trim(),
        run(&local, &["hostname"]).await?
    );
    Ok(())
}

#[tokio::test]
async fn live_every_metacharacter_survives_a_real_remote_shell() -> Result<()> {
    if !enabled() {
        return Ok(());
    }
    let remote = server().await?.host()?;

    // The assertion that matters: whatever goes in comes back byte-for-byte,
    // having crossed a real SSH connection and a real login shell. A failure
    // here is a command-injection bug, not a formatting nit.
    for argument in [
        "; rm -rf /",
        "&& whoami",
        "$(whoami)",
        "`whoami`",
        "$HOME",
        "${HOME}",
        "*",
        "it's",
        "a b\tc",
        "back\\slash",
        "\"double\"",
        "#hash",
        "",
    ] {
        let output = remote
            .run(&ExecRequest::new(["printf", "%s", argument]))
            .await?;

        assert!(output.succeeded(), "{}", output.stderr_lossy());
        assert_eq!(
            output.stdout_lossy(),
            argument,
            "argument {argument:?} was mangled in transit"
        );
    }
    Ok(())
}

#[tokio::test]
async fn live_a_working_directory_and_environment_apply_remotely() -> Result<()> {
    if !enabled() {
        return Ok(());
    }
    let remote = server().await?.host()?;

    let output = remote
        .run(
            &ExecRequest::new(["sh", "-c", "printf '%s %s' \"$PWD\" \"$GREETING\""])
                .with_cwd("/etc")
                .with_env("GREETING", "hello there"),
        )
        .await?;

    // SSH carries neither, so both had to be applied by the remote shell.
    assert_eq!(output.stdout_lossy(), "/etc hello there");
    Ok(())
}

#[tokio::test]
async fn live_a_missing_working_directory_fails_rather_than_running_elsewhere() -> Result<()> {
    if !enabled() {
        return Ok(());
    }
    let remote = server().await?.host()?;

    let output = remote
        .run(&ExecRequest::new(["pwd"]).with_cwd("/no-such-directory"))
        .await?;

    // `cd ... &&` rather than `;`: running a build in the wrong directory would
    // be worse than failing.
    assert!(!output.succeeded());
    assert!(output.stdout_lossy().trim().is_empty());
    Ok(())
}

#[tokio::test]
async fn live_a_remote_exit_status_comes_back() -> Result<()> {
    if !enabled() {
        return Ok(());
    }
    let remote = server().await?.host()?;

    let output = remote
        .run(&ExecRequest::new(["sh", "-c", "exit 7"]))
        .await?;

    assert_eq!(output.exit_code, 7);
    Ok(())
}

#[tokio::test]
async fn live_a_payload_reaches_the_remote_command() -> Result<()> {
    if !enabled() {
        return Ok(());
    }
    let remote = server().await?.host()?;

    let output = remote
        .run(&ExecRequest::new(["wc", "-c"]).with_stdin(vec![b'x'; 4096]))
        .await?;

    // This is what a workspace sync rides on.
    assert_eq!(output.stdout_lossy().trim(), "4096");
    Ok(())
}

#[tokio::test]
async fn live_a_workspace_syncs_and_then_skips() -> Result<()> {
    if !enabled() {
        return Ok(());
    }
    let remote = Arc::new(server().await?.host()?);

    let source = TempDir::new().map_err(|error| Error::io("tempdir", &error))?;
    std::fs::write(source.path().join("a.txt"), "alpha")
        .map_err(|error| Error::io("write", &error))?;
    std::fs::create_dir(source.path().join("nested"))
        .map_err(|error| Error::io("mkdir", &error))?;
    std::fs::write(source.path().join("nested/b.txt"), "beta")
        .map_err(|error| Error::io("write", &error))?;

    let syncer = tinybox_sync::Syncer::new(remote.clone());
    let first = syncer.sync(source.path(), "/root/work").await?;
    assert!(first.transferred());

    // The files really landed, checked by the far side rather than inferred.
    let listed = remote
        .run(&ExecRequest::new(["cat", "/root/work/nested/b.txt"]))
        .await?;
    assert_eq!(listed.stdout_lossy().trim(), "beta");

    // And a second sync with no edits sends nothing at all.
    let second = syncer.sync(source.path(), "/root/work").await?;
    assert!(!second.transferred());
    assert_eq!(first.fingerprint(), second.fingerprint());
    Ok(())
}

#[tokio::test]
async fn live_a_path_with_spaces_and_quotes_syncs_intact() -> Result<()> {
    if !enabled() {
        return Ok(());
    }
    let remote = Arc::new(server().await?.host()?);

    let source = TempDir::new().map_err(|error| Error::io("tempdir", &error))?;
    std::fs::write(source.path().join("a file with spaces.txt"), "spaced")
        .map_err(|error| Error::io("write", &error))?;

    // The destination itself contains a space, so the quoting has to hold for
    // the `mkdir` and `tar` commands too, not just for user arguments.
    let destination = "/root/my work";
    tinybox_sync::Syncer::new(remote.clone())
        .sync(source.path(), destination)
        .await?;

    let read = remote
        .run(&ExecRequest::new([
            "cat",
            "/root/my work/a file with spaces.txt",
        ]))
        .await?;
    assert_eq!(read.stdout_lossy().trim(), "spaced");
    Ok(())
}

#[tokio::test]
async fn live_an_unreachable_machine_fails_instead_of_hanging() -> Result<()> {
    if !enabled() {
        return Ok(());
    }
    let remote = SshHost::new(
        Arc::new(LocalHost::new()),
        SshTarget::new("root@127.0.0.1")?
            .with_port(1)
            .accepting_new_host_key(),
    );

    // BatchMode means no prompt, so this returns rather than waiting for a
    // password nobody is there to type.
    let output = remote.run(&ExecRequest::new(["true"])).await?;

    assert!(!output.succeeded());
    assert!(!output.stderr.is_empty());
    Ok(())
}

#[tokio::test]
async fn live_a_rejected_key_fails_without_prompting() -> Result<()> {
    if !enabled() {
        return Ok(());
    }
    let shared = server().await?;
    let keys = TempDir::new().map_err(|error| Error::io("tempdir", &error))?;
    let wrong = keys.path().join("wrong_ed25519");
    run(
        &LocalHost::new(),
        &[
            "ssh-keygen",
            "-t",
            "ed25519",
            "-N",
            "",
            "-q",
            "-f",
            &wrong.display().to_string(),
        ],
    )
    .await?;

    let remote = SshHost::new(
        Arc::new(LocalHost::new()),
        shared.target()?.with_identity(&wrong),
    );
    let output = remote.run(&ExecRequest::new(["true"])).await?;

    // The key the server does not know: refused, and quickly, without a prompt.
    assert!(!output.succeeded());
    Ok(())
}
