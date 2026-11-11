//! Tests for per-Create Docker egress detection.

use super::*;

use std::sync::Mutex;

use async_trait::async_trait;
use tinybox_core::{Error, ExecOutput, ExecRequest, HostExecutionLocation};

/// A host that answers the controller's probes from a script.
#[derive(Debug)]
struct ProbeHost {
    location: HostExecutionLocation,
    /// `docker info --format '{{.OSType}}|{{.OperatingSystem}}|{{json .SecurityOptions}}'`.
    docker_info: &'static str,
    /// Whether `sudo -n iptables|ip6tables -S <chain>` succeeds.
    sudo: bool,
    /// What `iptables|ip6tables -S FORWARD` lists.
    forward: &'static str,
    commands: Mutex<Vec<Vec<String>>>,
}

impl ProbeHost {
    fn rootful() -> Self {
        Self {
            location: HostExecutionLocation::Local,
            docker_info: "linux|Ubuntu 22.04.5 LTS|[\"name=apparmor\",\"name=seccomp,profile=builtin\"]",
            sudo: true,
            forward: "-P FORWARD DROP\n-A FORWARD -j DOCKER-USER\n-A FORWARD -j DOCKER-FORWARD\n",
            commands: Mutex::new(Vec::new()),
        }
    }

    fn commands(&self) -> Vec<Vec<String>> {
        self.commands
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

#[async_trait]
impl Host for ProbeHost {
    fn name(&self) -> &'static str {
        "probe"
    }

    fn execution_location(&self) -> HostExecutionLocation {
        self.location
    }

    async fn run(&self, request: &ExecRequest) -> Result<ExecOutput> {
        self.commands
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(request.argv.clone());
        let argv = &request.argv;
        if argv.iter().any(|part| part == "docker") {
            return Ok(ExecOutput::new(
                0,
                self.docker_info.as_bytes().to_vec(),
                Vec::new(),
            ));
        }
        if argv.iter().any(|part| part == "FORWARD") {
            return Ok(ExecOutput::new(
                0,
                self.forward.as_bytes().to_vec(),
                Vec::new(),
            ));
        }
        if self.sudo {
            Ok(ExecOutput::new(0, b"-N DOCKER-USER\n".to_vec(), Vec::new()))
        } else {
            Ok(ExecOutput::new(
                1,
                Vec::new(),
                b"sudo: a password is required\n".to_vec(),
            ))
        }
    }
}

fn allowlist() -> tinybox_bus::NetworkPolicy {
    tinybox_bus::NetworkPolicy::Allowlist(tinybox_bus::EgressAllowlist {
        hosts: vec!["api.example.com".to_owned()],
        ports: vec![443],
    })
}

/// The reason an allowlist was refused, or `None` for any other outcome.
async fn refusal(host: &ProbeHost) -> Option<String> {
    match docker_egress_controller("docker", &allowlist(), host).await {
        Err(Error::EgressAllowlistUnavailable { sandbox, reason }) if sandbox == "docker" => {
            Some(reason)
        }
        _ => None,
    }
}

#[tokio::test]
async fn other_backends_and_policies_skip_detection() -> Result<()> {
    let host = ProbeHost {
        sudo: false,
        ..ProbeHost::rootful()
    };
    for network in [
        tinybox_bus::NetworkPolicy::Denied,
        tinybox_bus::NetworkPolicy::Egress,
        tinybox_bus::NetworkPolicy::Open,
    ] {
        assert!(
            docker_egress_controller("docker", &network, &host)
                .await?
                .is_none()
        );
    }
    assert!(
        docker_egress_controller("namespace", &allowlist(), &host)
            .await?
            .is_none()
    );
    // No probe ran, so ordinary boxes are unaffected by the host's firewall.
    assert_eq!(host.commands(), Vec::<Vec<String>>::new());
    Ok(())
}

#[tokio::test]
async fn a_remote_host_is_refused_with_its_reason() {
    let host = ProbeHost {
        location: HostExecutionLocation::Remote,
        ..ProbeHost::rootful()
    };

    let reason = refusal(&host).await;

    assert!(
        reason
            .as_deref()
            .is_some_and(|reason| reason.contains("local execution host")),
        "{reason:?}"
    );
    assert_eq!(
        host.commands(),
        Vec::<Vec<String>>::new(),
        "nothing probed a remote host"
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_rootful_engine_with_passwordless_firewall_access_gets_a_controller() -> Result<()> {
    let host = ProbeHost::rootful();

    assert!(
        docker_egress_controller("docker", &allowlist(), &host)
            .await?
            .is_some()
    );
    assert!(
        host.commands()
            .iter()
            .any(|argv| argv.iter().map(String::as_str).eq([
                "sudo",
                "-n",
                "ip6tables",
                "-w",
                "5",
                "-S",
                "INPUT"
            ]))
    );
    Ok(())
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn each_missing_precondition_is_refused_with_its_own_reason() {
    let cases = [
        (
            ProbeHost {
                docker_info: "linux|Docker Desktop|[]",
                ..ProbeHost::rootful()
            },
            "native rootful Linux Engine",
        ),
        (
            ProbeHost {
                docker_info: "linux|Ubuntu 22.04.5 LTS|[\"name=rootless\"]",
                ..ProbeHost::rootful()
            },
            "native rootful Linux Engine",
        ),
        (
            ProbeHost {
                sudo: false,
                ..ProbeHost::rootful()
            },
            "root firewall chains are unavailable",
        ),
        (
            ProbeHost {
                forward: "-P FORWARD DROP\n-A FORWARD -j DOCKER-FORWARD\n-A FORWARD -j DOCKER-USER\n",
                ..ProbeHost::rootful()
            },
            "FORWARD",
        ),
    ];
    for (host, expected) in &cases {
        let reason = refusal(host).await;
        assert!(
            reason
                .as_deref()
                .is_some_and(|reason| reason.contains(expected)),
            "expected {expected:?}, got {reason:?}"
        );
    }
}

#[cfg(not(target_os = "linux"))]
#[tokio::test]
async fn a_non_linux_host_is_refused_with_its_reason() {
    let reason = refusal(&ProbeHost::rootful()).await;

    assert!(
        reason
            .as_deref()
            .is_some_and(|reason| reason.contains("only on Linux")),
        "{reason:?}"
    );
}

/// On a real rootful Linux Engine with passwordless `sudo` (CI's Docker
/// network job), detection installs the controller.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn live_detection_installs_the_controller_on_a_capable_host() -> Result<()> {
    if std::env::var_os("TINYBOX_LIVE_DOCKER").is_none() {
        return Ok(());
    }

    let controller =
        docker_egress_controller("docker", &allowlist(), &tinybox_host::LocalHost).await?;

    assert!(controller.is_some());
    Ok(())
}
