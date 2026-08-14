//! Tests for the SSH host.
//!
//! A [`RecordingHost`] stands in for the local machine, so the `ssh` command
//! line this host builds is assertable without a server. The live suite then
//! runs the same construction against a real `sshd`.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use async_trait::async_trait;
use tinybox_core::{Error, ExecOutput, ExecRequest, Host, Result};

use super::{NAME, SshHost, SshTarget};

/// A host that records what it was asked to run.
#[derive(Debug, Default)]
struct RecordingHost {
    seen: Mutex<Vec<ExecRequest>>,
}

impl RecordingHost {
    fn seen(&self) -> MutexGuard<'_, Vec<ExecRequest>> {
        self.seen.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn last(&self) -> Option<ExecRequest> {
        self.seen().last().cloned()
    }
}

#[async_trait]
impl Host for RecordingHost {
    fn name(&self) -> &'static str {
        "recording"
    }

    async fn run(&self, request: &ExecRequest) -> Result<ExecOutput> {
        self.seen().push(request.clone());
        Ok(ExecOutput::new(0, b"ok".to_vec(), Vec::new()))
    }
}

/// An SSH host over a recording inner host.
fn host() -> Result<(SshHost, Arc<RecordingHost>)> {
    let inner = Arc::new(RecordingHost::default());
    Ok((
        SshHost::new(inner.clone(), SshTarget::new("builder@example.invalid")?),
        inner,
    ))
}

/// The argv the inner host was last asked to run.
fn last_argv(inner: &RecordingHost) -> Vec<String> {
    inner.last().map(|request| request.argv).unwrap_or_default()
}

#[test]
fn it_reports_its_name() -> Result<()> {
    let (host, _inner) = host()?;

    assert_eq!(host.name(), "ssh");
    assert_eq!(host.name(), NAME);
    assert_eq!(host.target().destination(), "builder@example.invalid");
    Ok(())
}

#[tokio::test]
async fn a_command_is_run_through_ssh() -> Result<()> {
    let (host, inner) = host()?;

    let output = host.run(&ExecRequest::new(["uname", "-s"])).await?;

    assert_eq!(output.stdout_lossy(), "ok");
    let argv = last_argv(&inner);
    assert_eq!(argv[0], "ssh");
    assert!(argv.contains(&"builder@example.invalid".to_owned()));
    assert_eq!(argv.last().map(String::as_str), Some("'uname' '-s'"));
    Ok(())
}

#[tokio::test]
async fn it_never_prompts_and_never_allocates_a_terminal() -> Result<()> {
    let (host, inner) = host()?;

    host.run(&ExecRequest::new(["true"])).await?;

    let argv = last_argv(&inner);
    // A prompt in a program nobody is watching is a hang, not a failure.
    assert!(argv.windows(2).any(|pair| pair == ["-o", "BatchMode=yes"]));
    // No pty, so a tar stream is not corrupted by inserted carriage returns.
    assert!(argv.contains(&"-T".to_owned()));
    Ok(())
}

#[tokio::test]
async fn host_key_checking_is_left_alone_by_default() -> Result<()> {
    let (host, inner) = host()?;

    host.run(&ExecRequest::new(["true"])).await?;

    // Nothing here weakens authentication unless the caller asked for it.
    let argv = last_argv(&inner).join(" ");
    assert!(!argv.contains("StrictHostKeyChecking"));
    assert!(!argv.contains("UserKnownHostsFile"));
    Ok(())
}

#[tokio::test]
async fn accepting_a_new_host_key_is_opt_in_and_still_refuses_a_changed_one() -> Result<()> {
    let inner = Arc::new(RecordingHost::default());
    let host = SshHost::new(
        inner.clone(),
        SshTarget::new("throwaway")?.accepting_new_host_key(),
    );

    host.run(&ExecRequest::new(["true"])).await?;

    // `accept-new` trusts an unknown key; it does not ignore a changed one,
    // which is the case that means something is actually wrong.
    let argv = last_argv(&inner);
    assert!(
        argv.windows(2)
            .any(|pair| pair == ["-o", "StrictHostKeyChecking=accept-new"])
    );
    assert!(!argv.join(" ").contains("StrictHostKeyChecking=no"));
    Ok(())
}

#[tokio::test]
async fn a_port_and_identity_reach_the_command_line() -> Result<()> {
    let inner = Arc::new(RecordingHost::default());
    let host = SshHost::new(
        inner.clone(),
        SshTarget::new("machine")?
            .with_port(2222)
            .with_identity("/keys/id_ed25519"),
    );

    host.run(&ExecRequest::new(["true"])).await?;

    let argv = last_argv(&inner);
    assert!(argv.windows(2).any(|pair| pair == ["-p", "2222"]));
    assert!(
        argv.windows(2)
            .any(|pair| pair == ["-i", "/keys/id_ed25519"])
    );
    // With an explicit key, the agent must not offer others first and exhaust
    // the server's authentication attempt limit.
    assert!(
        argv.windows(2)
            .any(|pair| pair == ["-o", "IdentitiesOnly=yes"])
    );
    Ok(())
}

#[tokio::test]
async fn the_remote_command_is_separated_from_ssh_s_own_options() -> Result<()> {
    let (host, inner) = host()?;

    host.run(&ExecRequest::new(["-weird-program"])).await?;

    let argv = last_argv(&inner);
    let separator = argv.iter().position(|part| part == "--");
    // Everything after `--` belongs to the remote, so a command starting with a
    // dash cannot be read as an ssh flag.
    assert_eq!(
        separator.map(|index| index + 2),
        Some(argv.len()),
        "the remote command must be the only thing after `--`"
    );
    Ok(())
}

#[tokio::test]
async fn a_working_directory_and_environment_cross_the_connection() -> Result<()> {
    let (host, inner) = host()?;

    host.run(
        &ExecRequest::new(["make"])
            .with_cwd("/srv/work")
            .with_env("CI", "true"),
    )
    .await?;

    // SSH carries neither, so both are applied by the remote shell.
    assert_eq!(
        last_argv(&inner).last().map(String::as_str),
        Some("cd '/srv/work' && env 'CI=true' 'make'")
    );
    Ok(())
}

#[tokio::test]
async fn an_injection_attempt_arrives_as_one_argument() -> Result<()> {
    let (host, inner) = host()?;

    host.run(&ExecRequest::new(["echo", "; rm -rf /"])).await?;

    // The whole thing is one quoted word, so the remote shell sees data.
    assert_eq!(
        last_argv(&inner).last().map(String::as_str),
        Some("'echo' '; rm -rf /'")
    );
    Ok(())
}

#[tokio::test]
async fn a_payload_is_forwarded_for_the_remote_command_to_read() -> Result<()> {
    let (host, inner) = host()?;

    host.run(&ExecRequest::new(["tar", "-x"]).with_stdin("tar bytes"))
        .await?;

    // `ssh` forwards its own stdin to the far side, so syncing a workspace
    // needs no staging file on a machine tinybox may never reach again.
    assert_eq!(
        inner.last().and_then(|request| request.stdin),
        Some(b"tar bytes".to_vec())
    );
    Ok(())
}

#[tokio::test]
async fn a_command_with_no_program_is_refused_before_connecting() -> Result<()> {
    let (host, inner) = host()?;

    let empty: Vec<String> = Vec::new();
    assert_eq!(
        host.run(&ExecRequest::new(empty)).await.err(),
        Some(Error::EmptyCommand {
            sandbox: NAME.to_owned()
        })
    );
    assert!(inner.last().is_none(), "nothing should have been run");
    Ok(())
}

#[test]
fn a_destination_that_ssh_would_read_as_an_option_is_refused() {
    for bad in ["", "-oProxyCommand=touch /tmp/pwned", "-l"] {
        assert!(
            matches!(
                SshTarget::new(bad),
                Err(Error::InvalidIdentifier {
                    kind: "ssh destination",
                    ..
                })
            ),
            "{bad:?} should be rejected as a destination"
        );
    }
}

#[test]
fn ordinary_destinations_are_accepted() -> Result<()> {
    for good in [
        "machine",
        "user@machine",
        "user@10.0.0.1",
        "my-config-alias",
    ] {
        assert_eq!(SshTarget::new(good)?.destination(), good);
    }
    Ok(())
}

#[tokio::test]
async fn ssh_hosts_compose_to_reach_through_a_jump_box() -> Result<()> {
    let inner = Arc::new(RecordingHost::default());
    let jump = Arc::new(SshHost::new(inner.clone(), SshTarget::new("jump")?));
    let behind = SshHost::new(jump, SshTarget::new("private")?);

    behind.run(&ExecRequest::new(["hostname"])).await?;

    // The outer connection carries an inner one as its remote command, and no
    // code here knows what a jump box is.
    let argv = last_argv(&inner);
    assert!(argv.contains(&"jump".to_owned()));
    let remote = argv.last().cloned().unwrap_or_default();
    assert!(remote.contains("'ssh'"), "{remote}");
    assert!(remote.contains("'private'"), "{remote}");
    Ok(())
}

#[tokio::test]
async fn it_is_usable_behind_a_trait_object() -> Result<()> {
    let inner = Arc::new(RecordingHost::default());
    let host: Box<dyn Host> = Box::new(SshHost::new(inner, SshTarget::new("machine")?));

    assert_eq!(host.name(), "ssh");
    assert!(host.run(&ExecRequest::new(["true"])).await?.succeeded());
    Ok(())
}
