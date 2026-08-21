//! Tests for the SSH port forward.
//!
//! Driving a real tunnel needs a real sshd, which is `live_ssh.rs`'s job. What
//! is checked here is everything that does not: the flags chosen, the refusal a
//! chained host gets, and — by standing an ordinary child process in for `ssh`
//! — that waiting really does resolve when a listener appears and really does
//! give up when the child dies.

use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;

use async_trait::async_trait;
use tinybox_core::{Capability, Error, ExecOutput, ExecRequest, Host, Result};

use super::{SshTunnel, exit_diagnostic, tunnel_command, wait_until_listening};
use super::super::{SshHost, SshTarget};

/// A host that is not `local`, so an [`SshHost`] wrapping it is a chain.
#[derive(Debug)]
struct NotLocal;

#[async_trait]
impl Host for NotLocal {
    fn name(&self) -> &'static str {
        "ssh"
    }

    async fn run(&self, _request: &ExecRequest) -> Result<ExecOutput> {
        Ok(ExecOutput::new(0, Vec::new(), Vec::new()))
    }
}

/// A destination in a reserved TLD, so no test can reach a real machine.
fn target() -> Result<SshTarget> {
    SshTarget::new("builder@example.invalid")
}

/// Start `argv` as a stand-in for the `ssh` that would carry a tunnel.
fn stand_in(argv: &[&str]) -> Result<SshTunnel> {
    SshTunnel::spawn(&argv.iter().map(|a| (*a).to_owned()).collect::<Vec<_>>())
}

#[test]
fn the_tunnel_carries_only_the_forward() -> Result<()> {
    let argv = tunnel_command(&target()?, 54321, ([10, 0, 0, 5], 7788).into());

    // No remote command: a login shell on the far side is one more thing that
    // can fail, and this connection has no use for one.
    assert!(argv.contains(&"-N".to_owned()), "{argv:?}");
    // Without this, a refused forward leaves `ssh` connected and idle, which
    // looks exactly like success until the first connection attempt.
    assert!(argv.contains(&"ExitOnForwardFailure=yes".to_owned()), "{argv:?}");
    // The local side is loopback-only: a forward reachable from the network
    // would republish the far machine's port to anyone who can reach this one.
    let spec = argv.iter().position(|part| part == "-L").map(|at| &argv[at + 1]);
    assert_eq!(spec.map(String::as_str), Some("127.0.0.1:54321:10.0.0.5:7788"));
    // The destination is last, so nothing after it can be read as a flag.
    assert_eq!(argv.last().map(String::as_str), Some("builder@example.invalid"));
    Ok(())
}

#[test]
fn the_tunnel_inherits_the_targets_connection_settings() -> Result<()> {
    // A forward that ignored `--ssh-port` or `BatchMode` would behave
    // differently from every other command against the same target.
    let argv = tunnel_command(&target()?.with_port(2222), 1, ([127, 0, 0, 1], 2).into());

    assert!(argv.contains(&"BatchMode=yes".to_owned()), "{argv:?}");
    assert!(argv.contains(&"2222".to_owned()), "{argv:?}");
    Ok(())
}

#[tokio::test]
async fn waiting_resolves_as_soon_as_something_accepts() -> Result<()> {
    // A listener already bound stands in for the far side being reachable.
    let listener = TcpListener::bind(("127.0.0.1", 0)).map_err(|e| Error::io("bind", &e))?;
    let local: SocketAddr = listener.local_addr().map_err(|e| Error::io("addr", &e))?;
    let mut tunnel = stand_in(&["sleep", "30"])?;

    let outcome = wait_until_listening(&mut tunnel, local).await;

    tunnel.close();
    assert!(outcome.is_ok(), "{outcome:?}");
    Ok(())
}

#[tokio::test]
async fn a_tunnel_that_dies_is_reported_with_its_own_diagnostic() -> Result<()> {
    // Waiting out the full timeout for a process that has already exited would
    // turn a rejected key into a ten-second hang and then a message saying
    // nothing about why.
    let mut tunnel = stand_in(&["/bin/sh", "-c", "echo 'Permission denied' >&2; exit 255"])?;
    // Nothing will ever accept here; the child's death is what ends the wait.
    let unused = TcpListener::bind(("127.0.0.1", 0)).map_err(|e| Error::io("bind", &e))?;
    let local: SocketAddr = unused.local_addr().map_err(|e| Error::io("addr", &e))?;
    drop(unused);

    let outcome = wait_until_listening(&mut tunnel, local).await;

    match outcome.err() {
        Some(Error::Backend { message, .. }) => {
            assert!(message.contains("Permission denied"), "{message:?}");
        }
        other => assert_eq!(format!("{other:?}"), "a backend error"),
    }
    Ok(())
}

#[test]
fn a_silent_exit_still_says_something() -> Result<()> {
    // An error with no message is the least useful thing this could report.
    let mut tunnel = stand_in(&["/bin/sh", "-c", "exit 1"])?;
    let _ = tunnel.child.wait();

    assert_eq!(
        exit_diagnostic(&mut tunnel),
        "ssh exited before the forward was established"
    );
    Ok(())
}

#[test]
fn closing_a_tunnel_twice_is_harmless() -> Result<()> {
    // `Forward`'s `Drop` calls this, and a test may have called it already.
    let mut tunnel = stand_in(&["sleep", "30"])?;

    tunnel.close();
    tunnel.close();
    Ok(())
}

#[test]
fn a_missing_program_is_reported_rather_than_silently_absent() {
    let outcome = stand_in(&["tinybox-no-such-program-exists"]);

    assert!(matches!(outcome.err(), Some(Error::Io { .. })));
}

#[tokio::test]
async fn a_chained_host_refuses_rather_than_tunnelling_from_the_wrong_machine() -> Result<()> {
    // Every other operation composes, because it is a command line the inner
    // host runs. A tunnel is a process that has to keep running, so opening it
    // here would put it on this machine and report an address leading nowhere.
    let chained = SshHost::new(Arc::new(NotLocal), target()?);

    let outcome = chained.forward(([127, 0, 0, 1], 7788).into()).await;

    assert_eq!(
        outcome.err(),
        Some(Error::Unsupported {
            sandbox: "ssh".to_owned(),
            capability: Capability::PortForward,
        })
    );
    Ok(())
}

#[tokio::test]
async fn an_unreachable_destination_fails_instead_of_hanging() -> Result<()> {
    // `BatchMode=yes` is what makes this a failure rather than a password
    // prompt nobody is there to answer.
    let host = SshHost::new(Arc::new(tinybox_host::LocalHost::new()), target()?);

    let outcome = host.forward(([127, 0, 0, 1], 7788).into()).await.err();

    assert!(
        matches!(
            outcome,
            // The forward was refused or never started accepting, or there is
            // no `ssh` binary on this host to try it with.
            Some(
                Error::Backend {
                    operation: "open a port forward",
                    ..
                } | Error::Io { .. }
            )
        ),
        "unexpected outcome: {outcome:?}"
    );
    Ok(())
}
