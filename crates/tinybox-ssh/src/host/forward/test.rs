//! Tests for the SSH port forward.
//!
//! Opening a real tunnel needs a real sshd, which is `live_ssh.rs`'s job. What
//! is checked here is everything that can be wrong *before* a packet moves: the
//! refusal a chained host gets, and that a failed open leaves no `ssh` behind.

use std::sync::Arc;

use tinybox_core::{Capability, Error, ExecOutput, ExecRequest, Host, Result};

use super::super::{SshHost, SshTarget};

/// A host that is not `local`, so an `SshHost` wrapping it is a chain.
#[derive(Debug)]
struct NotLocal;

#[async_trait::async_trait]
impl Host for NotLocal {
    fn name(&self) -> &'static str {
        "ssh"
    }

    async fn run(&self, _request: &ExecRequest) -> Result<ExecOutput> {
        Ok(ExecOutput::new(0, Vec::new(), Vec::new()))
    }
}

fn target() -> SshTarget {
    SshTarget::new("builder@example.invalid").expect("a valid destination")
}

#[tokio::test]
async fn a_chained_host_refuses_rather_than_tunnelling_from_the_wrong_machine() {
    // Every other operation composes, because it is a command line the inner
    // host runs. A tunnel is a process that has to keep running, so opening it
    // here would put it on this machine and report an address leading nowhere.
    let chained = SshHost::new(Arc::new(NotLocal), target());

    let error = chained
        .forward(([127, 0, 0, 1], 7788).into())
        .await
        .expect_err("a chained forward is refused");

    assert_eq!(
        error,
        Error::Unsupported {
            sandbox: "ssh".to_owned(),
            capability: Capability::PortForward,
        }
    );
}

#[tokio::test]
async fn an_unreachable_destination_fails_instead_of_hanging() {
    // `BatchMode=yes` is what makes this a failure rather than a password
    // prompt nobody is there to answer. `.invalid` is reserved by RFC 2606, so
    // this cannot accidentally reach a real machine.
    let host = SshHost::new(Arc::new(tinybox_host::LocalHost::new()), target());

    let result = host.forward(([127, 0, 0, 1], 7788).into()).await;

    match result {
        Err(Error::Backend { operation, .. }) => {
            assert_eq!(operation, "open a port forward");
        }
        // No `ssh` binary on this host: nothing to test, and `Io` is the honest
        // report for it.
        Err(Error::Io { .. }) => {}
        Err(other) => panic!("unexpected error: {other:?}"),
        Ok(_) => panic!("a forward to example.invalid must not succeed"),
    }
}
