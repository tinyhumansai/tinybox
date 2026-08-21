//! Making a port on the far machine reachable from this one.
//!
//! Everything else in this crate builds a command line and hands it to an inner
//! [`Host`](tinybox_core::Host) to run to completion. A tunnel cannot work that
//! way: it *is* the running process, and it has to outlive the call that
//! created it. So this module spawns `ssh -N -L` directly and hands the child
//! to a [`Forward`] guard, which kills it on drop.

use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use tinybox_core::{Error, Forward, ForwardGuard, Result};

use super::target::SshTarget;

/// How long to wait for the tunnel's local listener to start accepting.
///
/// `ssh` binds the local side before the far side matters, so this is waiting
/// on authentication and the forward request, not on whatever is listening
/// over there. Reaching *that* is the caller's own health check to make.
const LISTEN_TIMEOUT: Duration = Duration::from_secs(10);

/// How often to retry the local connect while waiting.
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// An `ssh -N -L` child, killed when the [`Forward`] holding it is dropped.
#[derive(Debug)]
struct SshTunnel {
    child: Child,
}

impl ForwardGuard for SshTunnel {
    fn close(&mut self) {
        // Both results are deliberately ignored: a tunnel whose `ssh` already
        // exited is closed, which is the state this method exists to reach.
        // `wait` follows `kill` so the child is reaped rather than left a
        // zombie for the lifetime of the host process.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Reserve a free port on the loopback interface.
///
/// Binding and immediately closing is the portable way to have the operating
/// system choose; `ssh -L` cannot report back a port it chose itself, so the
/// choice has to be made here. The gap between closing and `ssh` binding is a
/// race in principle. In practice nothing else is handing out ephemeral ports
/// in that window, and `ExitOnForwardFailure` turns a lost race into an
/// immediate failure rather than a tunnel to nowhere.
fn reserve_local_port() -> Result<u16> {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .map_err(|error| Error::io("bind a local port", &error))?;
    let port = listener
        .local_addr()
        .map_err(|error| Error::io("read the local port", &error))?
        .port();
    drop(listener);
    Ok(port)
}

/// Open a tunnel from a local loopback port to `remote` on `target`.
///
/// # Errors
///
/// Returns [`Error::Io`] when a local port cannot be reserved or `ssh` cannot
/// be started, and [`Error::Backend`] when the tunnel does not begin accepting
/// connections within [`LISTEN_TIMEOUT`] — which is what a rejected key or a
/// refused forward looks like from here.
pub(super) fn open(target: &SshTarget, remote: SocketAddr) -> Result<Forward> {
    let local_port = reserve_local_port()?;
    let local: SocketAddr = ([127, 0, 0, 1], local_port).into();

    let mut command = Command::new("ssh");
    command.args(target.connection_flags());
    // Do not run a remote command: this connection exists only to carry the
    // forward, and a login shell on the far side would be one more thing to
    // fail.
    command.arg("-N");
    // Fail loudly rather than sitting there connected with no forward, which
    // would look identical to success until the first connection attempt.
    command.arg("-o");
    command.arg("ExitOnForwardFailure=yes");
    // Notice a dead peer instead of holding a tunnel that stopped working.
    command.arg("-o");
    command.arg("ServerAliveInterval=15");
    command.arg("-L");
    command.arg(format!(
        "127.0.0.1:{local_port}:{}:{}",
        remote.ip(),
        remote.port()
    ));
    command.arg(target.destination());
    command.stdin(Stdio::null());
    command.stdout(Stdio::null());
    command.stderr(Stdio::piped());

    let child = command
        .spawn()
        .map_err(|error| Error::io("spawn ssh for a port forward", &error))?;
    let mut tunnel = SshTunnel { child };

    match wait_until_listening(&mut tunnel, local) {
        Ok(()) => Ok(Forward::guarded(local, Box::new(tunnel))),
        Err(error) => {
            // Do not leave an `ssh` behind for a forward the caller will never
            // be handed.
            tunnel.close();
            Err(error)
        }
    }
}

/// Block until something accepts on `local`, or the tunnel dies, or time runs
/// out.
fn wait_until_listening(tunnel: &mut SshTunnel, local: SocketAddr) -> Result<()> {
    let deadline = Instant::now() + LISTEN_TIMEOUT;
    loop {
        if TcpStream::connect_timeout(&local, POLL_INTERVAL).is_ok() {
            return Ok(());
        }
        // An `ssh` that has already exited is never going to start listening,
        // so report its own diagnostic instead of waiting out the deadline.
        if let Ok(Some(_)) = tunnel.child.try_wait() {
            return Err(Error::Backend {
                sandbox: super::NAME.to_owned(),
                operation: "open a port forward",
                message: exit_diagnostic(tunnel),
            });
        }
        if Instant::now() >= deadline {
            return Err(Error::Backend {
                sandbox: super::NAME.to_owned(),
                operation: "open a port forward",
                message: format!(
                    "the forward did not start accepting on {local} within {}s",
                    LISTEN_TIMEOUT.as_secs()
                ),
            });
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

/// Whatever `ssh` said on its way out.
///
/// Falls back to a description rather than an empty string: an error with no
/// message is the least useful thing this could report.
fn exit_diagnostic(tunnel: &mut SshTunnel) -> String {
    use std::io::Read as _;

    let mut text = String::new();
    if let Some(stderr) = tunnel.child.stderr.as_mut() {
        let _ = stderr.read_to_string(&mut text);
    }
    let trimmed = text.trim();
    if trimmed.is_empty() {
        "ssh exited before the forward was established".to_owned()
    } else {
        trimmed.to_owned()
    }
}

#[cfg(test)]
mod forward_test;
