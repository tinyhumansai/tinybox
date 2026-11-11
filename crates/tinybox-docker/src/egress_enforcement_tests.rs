//! Tests for native Docker egress filter capability checks.

use std::{
    fmt::Write as _,
    net::IpAddr,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use tinybox_core::{BoxId, Error, ExecOutput, ExecRequest, Host, HostExecutionLocation, Result};

use super::{
    DockerEgressController, NativeLinuxDockerEgressController, NetworkNames, deny_rules,
    force_local_rootful_docker, scope_token, stable_hash, verify_created_bridge_link,
};
use crate::EgressResolver;

#[derive(Debug)]
struct FakeNativeHost {
    missing_forward_hook: &'static str,
    commands: Mutex<Vec<Vec<String>>>,
}

impl FakeNativeHost {
    fn new(missing_forward_hook: &'static str) -> Self {
        Self {
            missing_forward_hook,
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
impl Host for FakeNativeHost {
    fn name(&self) -> &'static str {
        "fake-native"
    }

    fn execution_location(&self) -> HostExecutionLocation {
        HostExecutionLocation::Local
    }

    async fn run(&self, request: &ExecRequest) -> Result<ExecOutput> {
        self.commands
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(request.argv.clone());

        let is_missing_hook = request.argv.iter().any(|part| part == "-C")
            && request.argv.iter().any(|part| part == "FORWARD")
            && request.argv.iter().any(|part| part == "DOCKER-USER")
            && request
                .argv
                .iter()
                .any(|part| part == self.missing_forward_hook);
        if request.argv.iter().any(|part| part == "docker") {
            return Ok(ExecOutput::new(
                0,
                b"linux|Ubuntu 26.04|[]".to_vec(),
                Vec::new(),
            ));
        }
        if is_missing_hook {
            return Ok(ExecOutput::new(1, Vec::new(), b"rule not found".to_vec()));
        }
        if request.argv.iter().any(|part| part == "FORWARD")
            && request.argv.iter().any(|part| part == "-S")
        {
            let firewall = if request.argv.iter().any(|part| part == "ip6tables") {
                "ip6tables"
            } else {
                "iptables"
            };
            let rules = if firewall == self.missing_forward_hook {
                "-P FORWARD DROP\n-A FORWARD -j DOCKER-FORWARD\n"
            } else {
                "-P FORWARD DROP\n-A FORWARD -j DOCKER-USER\n-A FORWARD -j DOCKER-FORWARD\n"
            };
            return Ok(ExecOutput::new(0, rules.as_bytes().to_vec(), Vec::new()));
        }
        Ok(ExecOutput::new(0, b"chain exists\n".to_vec(), Vec::new()))
    }
}

#[derive(Debug)]
struct Resolver;

impl EgressResolver for Resolver {
    fn resolve(&self, _hostname: &str) -> std::io::Result<Vec<IpAddr>> {
        Ok(vec![
            IpAddr::from([203, 0, 113, 8]),
            IpAddr::from([203, 0, 113, 9]),
        ])
    }
}

#[test]
fn local_docker_daemon_pinning_is_idempotent() {
    let command = vec!["docker".to_owned(), "info".to_owned()];
    let pinned = force_local_rootful_docker(command);

    assert_eq!(force_local_rootful_docker(pinned.clone()), pinned);
}

#[test]
fn workload_docker_host_arguments_do_not_bypass_daemon_pinning() {
    let command = vec![
        "docker".to_owned(),
        "run".to_owned(),
        "image".to_owned(),
        "echo".to_owned(),
        "--host".to_owned(),
        "unix:///var/run/docker.sock".to_owned(),
    ];

    let pinned = force_local_rootful_docker(command);
    let run = pinned
        .iter()
        .position(|part| part == "run")
        .unwrap_or(pinned.len());
    assert!(
        pinned[..run]
            .windows(2)
            .any(|pair| { pair == ["--host", "unix:///var/run/docker.sock"] })
    );
    assert_eq!(
        pinned[run..],
        [
            "run",
            "image",
            "echo",
            "--host",
            "unix:///var/run/docker.sock"
        ]
    );
}

#[derive(Debug)]
#[cfg(target_os = "linux")]
struct MappedIpv4Resolver;

#[cfg(target_os = "linux")]
impl EgressResolver for MappedIpv4Resolver {
    fn resolve(&self, _hostname: &str) -> std::io::Result<Vec<IpAddr>> {
        Ok(vec!["::ffff:203.0.113.11".parse().map_err(|error| {
            std::io::Error::other(format!("invalid fixture: {error}"))
        })?])
    }
}

#[derive(Debug)]
struct BridgeLinkHost {
    exists: bool,
}

#[derive(Debug, Clone, Copy)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
enum NetworkCreateBehavior {
    Succeed,
    CommandFailure,
    CommandFailureAfterSideEffect,
    HostErrorAfterSideEffect,
}

#[derive(Debug, Clone, Copy)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
enum NetworkInspectBehavior {
    Owned,
    Absent,
    Foreign,
    Uncertain,
    Malformed,
}

#[derive(Debug)]
struct PreparedNativeHost {
    commands: Mutex<Vec<Vec<String>>>,
    chains: Mutex<std::collections::BTreeSet<(String, String)>>,
    marked_chains: Mutex<std::collections::BTreeSet<(String, String)>>,
    chains_with_rules: Mutex<std::collections::BTreeSet<(String, String)>>,
    network_create_behavior: NetworkCreateBehavior,
    network_inspect_behavior: NetworkInspectBehavior,
    missing_final_drop: Option<String>,
    empty_network_create: bool,
    fail_chain_marker: bool,
    #[cfg(target_os = "linux")]
    no_matching_hooks: bool,
    #[cfg(target_os = "linux")]
    fail_chain_delete_once: Mutex<bool>,
    #[cfg(target_os = "linux")]
    fail_network_remove_once: Mutex<bool>,
    network_owner: String,
    network_scope: String,
    network_attempt: String,
    network_subnets: String,
    chain_owner_token: String,
    bridge: String,
    forward_chain: String,
    input_chain: String,
}

impl PreparedNativeHost {
    fn new(id: &BoxId, names: &NetworkNames) -> Self {
        Self {
            commands: Mutex::new(Vec::new()),
            chains: Mutex::new(std::collections::BTreeSet::new()),
            marked_chains: Mutex::new(std::collections::BTreeSet::new()),
            chains_with_rules: Mutex::new(std::collections::BTreeSet::new()),
            network_create_behavior: NetworkCreateBehavior::Succeed,
            network_inspect_behavior: NetworkInspectBehavior::Owned,
            missing_final_drop: None,
            empty_network_create: false,
            fail_chain_marker: false,
            #[cfg(target_os = "linux")]
            no_matching_hooks: false,
            #[cfg(target_os = "linux")]
            fail_chain_delete_once: Mutex::new(false),
            #[cfg(target_os = "linux")]
            fail_network_remove_once: Mutex::new(false),
            network_owner: id.to_string(),
            network_scope: names.owner_token.clone(),
            network_attempt: names.attempt_token.clone(),
            network_subnets: r#"[{"Subnet":"172.18.0.0/16"},{"Subnet":"fd00:dead:beef::/64"}]"#
                .to_owned(),
            chain_owner_token: names.chain_owner_token.clone(),
            bridge: names.bridge.clone(),
            forward_chain: names.forward_chain.clone(),
            input_chain: names.input_chain.clone(),
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
#[allow(clippy::too_many_lines)] // The fake host models the firewall and Docker command surface.
impl Host for PreparedNativeHost {
    fn name(&self) -> &'static str {
        "prepared-native"
    }

    fn execution_location(&self) -> HostExecutionLocation {
        HostExecutionLocation::Local
    }

    async fn run(&self, request: &ExecRequest) -> Result<ExecOutput> {
        let argv = &request.argv;
        self.commands
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(argv.clone());
        if let Some(docker_index) = argv.iter().position(|arg| arg == "docker") {
            let docker_args = &argv[docker_index + 1..];
            if docker_args.iter().any(|arg| arg == "info") {
                return Ok(ExecOutput::new(
                    0,
                    b"linux|Ubuntu 26.04|[]".to_vec(),
                    Vec::new(),
                ));
            }
            if docker_args.iter().any(|arg| arg == "network") {
                #[cfg(target_os = "linux")]
                if docker_args.iter().any(|arg| arg == "rm")
                    && *self
                        .fail_network_remove_once
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                {
                    *self
                        .fail_network_remove_once
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = false;
                    return Ok(ExecOutput::new(
                        1,
                        Vec::new(),
                        b"injected network removal failure".to_vec(),
                    ));
                }
                if docker_args.iter().any(|arg| arg == "create") {
                    if matches!(
                        self.network_create_behavior,
                        NetworkCreateBehavior::CommandFailure
                    ) {
                        return Ok(ExecOutput::new(
                            1,
                            Vec::new(),
                            b"network name already exists".to_vec(),
                        ));
                    }
                    if matches!(
                        self.network_create_behavior,
                        NetworkCreateBehavior::CommandFailureAfterSideEffect
                    ) {
                        return Ok(ExecOutput::new(
                            1,
                            Vec::new(),
                            b"simulated lost command response after network creation".to_vec(),
                        ));
                    }
                    if matches!(
                        self.network_create_behavior,
                        NetworkCreateBehavior::HostErrorAfterSideEffect
                    ) {
                        return Err(Error::Backend {
                            sandbox: "fake-native".to_owned(),
                            operation: "run Docker network create",
                            message: "simulated lost command response after create".to_owned(),
                        });
                    }
                    let network_id = if self.empty_network_create {
                        Vec::new()
                    } else {
                        b"network-id".to_vec()
                    };
                    return Ok(ExecOutput::new(0, network_id, Vec::new()));
                }
                if let Some(inspect_index) = docker_args.iter().position(|arg| arg == "inspect") {
                    match self.network_inspect_behavior {
                        NetworkInspectBehavior::Absent => {
                            return Ok(ExecOutput::new(
                                1,
                                Vec::new(),
                                b"Error: No such network".to_vec(),
                            ));
                        }
                        NetworkInspectBehavior::Uncertain => {
                            return Ok(ExecOutput::new(
                                1,
                                Vec::new(),
                                b"Error: daemon temporarily unavailable".to_vec(),
                            ));
                        }
                        NetworkInspectBehavior::Owned
                        | NetworkInspectBehavior::Foreign
                        | NetworkInspectBehavior::Malformed => {}
                    }
                    let format = docker_args
                        .get(inspect_index + 2)
                        .map_or("", String::as_str);
                    let owner = if matches!(
                        self.network_inspect_behavior,
                        NetworkInspectBehavior::Foreign
                    ) {
                        "another-box"
                    } else {
                        &self.network_owner
                    };
                    let stdout = if matches!(
                        self.network_inspect_behavior,
                        NetworkInspectBehavior::Malformed
                    ) {
                        "network-id|owner-without-scope".to_owned()
                    } else if format.contains(".Id") {
                        format!(
                            "network-id|{owner}|{}|{}",
                            self.network_scope, self.network_attempt
                        )
                    } else if format.contains(".Driver") {
                        format!(
                            "bridge|true|{}|{}|{}|{}",
                            self.bridge, owner, self.network_scope, self.network_attempt
                        )
                    } else if format.contains(".IPAM.Config") {
                        self.network_subnets.clone()
                    } else {
                        format!("{owner}|{}|{}", self.network_scope, self.network_attempt)
                    };
                    return Ok(ExecOutput::new(0, stdout.into_bytes(), Vec::new()));
                }
            }
        }

        if argv.first().is_some_and(|arg| arg == "ip") {
            return Ok(ExecOutput::new(
                0,
                format!("17: {}: <BROADCAST,MULTICAST,UP>\n", self.bridge).into_bytes(),
                Vec::new(),
            ));
        }

        if argv
            .iter()
            .any(|arg| arg == "iptables" || arg == "ip6tables")
        {
            #[cfg(target_os = "linux")]
            if self.no_matching_hooks && argv.iter().any(|arg| arg == "-C") {
                return Ok(ExecOutput::new(1, Vec::new(), b"rule not found".to_vec()));
            }
            #[cfg(target_os = "linux")]
            if let Some(index) = argv.iter().position(|arg| arg == "-F")
                && let Some(chain) = argv.get(index + 1)
            {
                let firewall = argv
                    .iter()
                    .find(|arg| matches!(arg.as_str(), "iptables" | "ip6tables"))
                    .cloned()
                    .unwrap_or_default();
                self.marked_chains
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .remove(&(firewall.clone(), chain.clone()));
                self.chains_with_rules
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .remove(&(firewall, chain.clone()));
            }
            #[cfg(target_os = "linux")]
            if *self
                .fail_chain_delete_once
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                && let Some(index) = argv.iter().position(|arg| arg == "-X")
                && let Some(chain) = argv.get(index + 1)
            {
                *self
                    .fail_chain_delete_once
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = false;
                if chain == &self.forward_chain {
                    return Ok(ExecOutput::new(
                        1,
                        Vec::new(),
                        b"injected chain delete failure".to_vec(),
                    ));
                }
            }
            if let Some(index) = argv.iter().position(|arg| arg == "-N")
                && let Some(chain) = argv.get(index + 1)
            {
                let firewall = argv
                    .iter()
                    .find(|arg| matches!(arg.as_str(), "iptables" | "ip6tables"))
                    .cloned()
                    .unwrap_or_default();
                self.chains
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .insert((firewall, chain.clone()));
            }
            if let Some(index) = argv.iter().position(|arg| arg == "-X")
                && let Some(chain) = argv.get(index + 1)
            {
                let firewall = argv
                    .iter()
                    .find(|arg| matches!(arg.as_str(), "iptables" | "ip6tables"))
                    .cloned()
                    .unwrap_or_default();
                self.chains
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .remove(&(firewall.clone(), chain.clone()));
                self.marked_chains
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .remove(&(firewall.clone(), chain.clone()));
                self.chains_with_rules
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .remove(&(firewall, chain.clone()));
            }
            if self.fail_chain_marker
                && argv
                    .windows(2)
                    .any(|args| args == ["--comment", &self.chain_owner_token])
            {
                return Ok(ExecOutput::new(
                    1,
                    Vec::new(),
                    b"injected owner marker failure".to_vec(),
                ));
            }
            if argv.iter().any(|arg| arg == "--comment")
                && let Some(index) = argv.iter().position(|arg| arg == "-A")
                && let Some(chain) = argv.get(index + 1)
            {
                let firewall = argv
                    .iter()
                    .find(|arg| matches!(arg.as_str(), "iptables" | "ip6tables"))
                    .cloned()
                    .unwrap_or_default();
                self.marked_chains
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .insert((firewall.clone(), chain.clone()));
                self.chains_with_rules
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .insert((firewall, chain.clone()));
            } else if let Some(index) = argv.iter().position(|arg| arg == "-A")
                && let Some(chain) = argv.get(index + 1)
            {
                let firewall = argv
                    .iter()
                    .find(|arg| matches!(arg.as_str(), "iptables" | "ip6tables"))
                    .cloned()
                    .unwrap_or_default();
                self.chains_with_rules
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .insert((firewall, chain.clone()));
            }
            if argv.iter().any(|arg| arg == "FORWARD") {
                return Ok(ExecOutput::new(
                    0,
                    b"-P FORWARD DROP\n-A FORWARD -j DOCKER-USER\n-A FORWARD -j DOCKER-FORWARD\n"
                        .to_vec(),
                    Vec::new(),
                ));
            }
            if argv.iter().any(|arg| arg == "-S") {
                let firewall = argv
                    .iter()
                    .find(|arg| matches!(arg.as_str(), "iptables" | "ip6tables"))
                    .cloned()
                    .unwrap_or_default();
                let chains = self
                    .chains
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let marked_chains = self
                    .marked_chains
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let chains_with_rules = self
                    .chains_with_rules
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let stdout = [&self.forward_chain, &self.input_chain]
                    .into_iter()
                    .filter(|chain| chains.contains(&(firewall.clone(), (*chain).clone())))
                    .fold(String::new(), |mut stdout, chain| {
                        let _ = writeln!(stdout, "-N {chain}");
                        if marked_chains.contains(&(firewall.clone(), chain.clone())) {
                            let _ = writeln!(
                                stdout,
                                "-A {chain} -s 0.0.0.0/32 -m comment --comment {} -j DROP",
                                self.chain_owner_token
                            );
                        }
                        if chains_with_rules.contains(&(firewall.clone(), chain.clone()))
                            && self.missing_final_drop.as_deref() != Some(chain)
                        {
                            let _ = writeln!(stdout, "-A {chain} -j DROP");
                        }
                        stdout
                    });
                return Ok(ExecOutput::new(0, stdout.into_bytes(), Vec::new()));
            }
            return Ok(ExecOutput::new(0, Vec::new(), Vec::new()));
        }

        Ok(ExecOutput::new(0, Vec::new(), Vec::new()))
    }
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn owner_marker_drop_does_not_satisfy_default_drop_verification() -> Result<()> {
    let id = BoxId::new("box-marker-is-not-default-drop")?;
    let namespace = "test";
    let names = NetworkNames::for_box(namespace, &id);
    let mut host = PreparedNativeHost::new(&id, &names);
    host.missing_final_drop = Some(names.forward_chain.clone());
    let controller = NativeLinuxDockerEgressController::new(Arc::new(Resolver));
    let allowlist = tinybox_core::EgressAllowlist::new(["service.test"], [443]);

    assert!(matches!(
        controller.prepare(&host, namespace, &id, &allowlist).await,
        Err(Error::EgressAllowlistUnavailable { .. })
    ));
    assert!(host.commands().iter().any(|argv| {
        argv.iter().any(|arg| arg == "rm") && argv.iter().any(|arg| arg == &names.network)
    }));
    Ok(())
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn uncertain_network_create_removes_only_the_verified_owned_network() -> Result<()> {
    let id = BoxId::new("box-create-response-lost")?;
    let namespace = "test";
    let names = NetworkNames::for_box(namespace, &id);
    let mut host = PreparedNativeHost::new(&id, &names);
    host.network_create_behavior = NetworkCreateBehavior::HostErrorAfterSideEffect;
    let controller = NativeLinuxDockerEgressController::new(Arc::new(Resolver));
    let allowlist = tinybox_core::EgressAllowlist::new(["service.test"], [443]);

    let result = controller.prepare(&host, namespace, &id, &allowlist).await;

    assert!(matches!(
        result,
        Err(Error::Backend {
            operation: "run Docker network create",
            ref message,
            ..
        }) if message.contains("simulated lost command response")
    ));
    let commands = host.commands();
    assert!(commands.iter().any(|argv| {
        argv.iter().any(|arg| arg == "inspect") && argv.iter().any(|arg| arg.contains("{{.Id}}"))
    }));
    assert!(commands.iter().any(|argv| {
        argv.iter().any(|arg| arg == "rm") && argv.iter().any(|arg| arg == "network-id")
    }));
    assert!(!commands.iter().any(|argv| {
        argv.iter()
            .any(|arg| matches!(arg.as_str(), "-A" | "-D" | "-F" | "-X"))
    }));
    Ok(())
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn ambiguous_create_retains_cleanup_error_when_owned_network_removal_fails() -> Result<()> {
    let id = BoxId::new("box-create-remove-fails")?;
    let namespace = "test";
    let names = NetworkNames::for_box(namespace, &id);
    let mut host = PreparedNativeHost::new(&id, &names);
    host.network_create_behavior = NetworkCreateBehavior::HostErrorAfterSideEffect;
    *host
        .fail_network_remove_once
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
    let controller = NativeLinuxDockerEgressController::new(Arc::new(Resolver));
    let allowlist = tinybox_core::EgressAllowlist::new(["service.test"], [443]);

    let result = controller.prepare(&host, namespace, &id, &allowlist).await;
    assert!(
        matches!(
            result,
            Err(Error::EgressRollbackFailed {
                ref message,
                ..
        }) if message.contains("simulated lost command response")
        ),
        "{result:?}; commands={:?}",
        host.commands()
    );
    assert_eq!(
        host.commands()
            .iter()
            .filter(|argv| argv.iter().any(|arg| arg == "inspect")
                && argv.iter().any(|arg| arg.contains("{{.Id}}")))
            .count(),
        2
    );
    Ok(())
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn ambiguous_create_preserves_same_box_network_from_an_older_attempt() -> Result<()> {
    let id = BoxId::new("box-create-old-attempt")?;
    let namespace = "test";
    let names = NetworkNames::for_box(namespace, &id);
    let mut host = PreparedNativeHost::new(&id, &names);
    host.network_create_behavior = NetworkCreateBehavior::HostErrorAfterSideEffect;
    host.network_attempt = "older-attempt-token".to_owned();
    let controller = NativeLinuxDockerEgressController::new(Arc::new(Resolver));
    let allowlist = tinybox_core::EgressAllowlist::new(["service.test"], [443]);

    assert!(
        controller
            .prepare(&host, namespace, &id, &allowlist)
            .await
            .is_err()
    );
    let commands = host.commands();
    assert!(commands.iter().any(|argv| {
        argv.iter().any(|arg| arg == "inspect")
            && argv
                .iter()
                .any(|arg| arg.contains("ai.tinyhumans.tinybox.egress.attempt"))
    }));
    assert!(
        !commands
            .iter()
            .any(|argv| argv.iter().any(|arg| arg == "rm"))
    );
    Ok(())
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn ambiguous_network_create_keeps_the_original_error_when_absent_or_foreign() -> Result<()> {
    for absent in [false, true] {
        let id = BoxId::new(if absent {
            "box-create-absent"
        } else {
            "box-create-foreign"
        })?;
        let namespace = "test";
        let names = NetworkNames::for_box(namespace, &id);
        let mut host = PreparedNativeHost::new(&id, &names);
        host.network_create_behavior = NetworkCreateBehavior::HostErrorAfterSideEffect;
        host.network_inspect_behavior = if absent {
            NetworkInspectBehavior::Absent
        } else {
            NetworkInspectBehavior::Foreign
        };
        let controller = NativeLinuxDockerEgressController::new(Arc::new(Resolver));
        let allowlist = tinybox_core::EgressAllowlist::new(["service.test"], [443]);

        assert!(matches!(
            controller.prepare(&host, namespace, &id, &allowlist).await,
            Err(Error::Backend {
                operation: "run Docker network create",
                ref message,
                ..
            }) if message.contains("simulated lost command response")
        ));
        assert!(
            !host
                .commands()
                .iter()
                .any(|argv| { argv.iter().any(|arg| arg == "rm") })
        );
    }
    Ok(())
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn ambiguous_network_create_reports_rollback_uncertainty_when_inspection_fails() -> Result<()>
{
    let id = BoxId::new("box-create-inspect-uncertain")?;
    let namespace = "test";
    let names = NetworkNames::for_box(namespace, &id);
    let mut host = PreparedNativeHost::new(&id, &names);
    host.network_create_behavior = NetworkCreateBehavior::HostErrorAfterSideEffect;
    host.network_inspect_behavior = NetworkInspectBehavior::Uncertain;
    let controller = NativeLinuxDockerEgressController::new(Arc::new(Resolver));
    let allowlist = tinybox_core::EgressAllowlist::new(["service.test"], [443]);

    assert!(matches!(
        controller.prepare(&host, namespace, &id, &allowlist).await,
        Err(Error::EgressRollbackFailed {
            ref message,
            ..
        }) if message.contains("simulated lost command response")
            && message.contains("daemon temporarily unavailable")
    ));
    assert!(
        !host
            .commands()
            .iter()
            .any(|argv| { argv.iter().any(|arg| arg == "rm") })
    );
    Ok(())
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn ambiguous_network_create_retains_ownership_uncertainty_for_malformed_inspection()
-> Result<()> {
    let id = BoxId::new("box-create-inspect-malformed")?;
    let namespace = "test";
    let names = NetworkNames::for_box(namespace, &id);
    let mut host = PreparedNativeHost::new(&id, &names);
    host.network_create_behavior = NetworkCreateBehavior::HostErrorAfterSideEffect;
    host.network_inspect_behavior = NetworkInspectBehavior::Malformed;
    let controller = NativeLinuxDockerEgressController::new(Arc::new(Resolver));
    let allowlist = tinybox_core::EgressAllowlist::new(["service.test"], [443]);

    assert!(matches!(
        controller.prepare(&host, namespace, &id, &allowlist).await,
        Err(Error::EgressRollbackFailed {
            ref message,
            ..
        }) if message.contains("missing or malformed network identity")
    ));
    assert!(
        !host
            .commands()
            .iter()
            .any(|argv| { argv.iter().any(|arg| arg == "rm") })
    );
    Ok(())
}

#[async_trait]
impl Host for BridgeLinkHost {
    fn name(&self) -> &'static str {
        "bridge-link-host"
    }

    fn execution_location(&self) -> HostExecutionLocation {
        HostExecutionLocation::Local
    }

    async fn run(&self, request: &ExecRequest) -> Result<ExecOutput> {
        let bridge = request.argv.last().map_or("", String::as_str);
        if self.exists {
            Ok(ExecOutput::new(
                0,
                format!("17: {bridge}: <BROADCAST,MULTICAST,UP>\n").into_bytes(),
                Vec::new(),
            ))
        } else {
            Ok(ExecOutput::new(1, Vec::new(), b"Device not found".to_vec()))
        }
    }
}

#[test]
fn allowlist_protocol_set_is_tcp_only() {
    assert_eq!(&super::ALLOWLIST_PROTOCOLS[..], &["tcp"]);
}

#[tokio::test]
async fn missing_local_bridge_link_refuses_enforcement() -> Result<()> {
    let names = NetworkNames::for_box("test", &BoxId::new("box-0")?);
    let host = BridgeLinkHost { exists: false };

    assert!(matches!(
        verify_created_bridge_link(&host, &names).await,
        Err(Error::EgressAllowlistUnavailable { .. })
    ));
    Ok(())
}

#[tokio::test]
async fn existing_local_bridge_link_is_verified() -> Result<()> {
    let names = NetworkNames::for_box("test", &BoxId::new("box-0")?);
    let host = BridgeLinkHost { exists: true };

    verify_created_bridge_link(&host, &names).await
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn native_controller_prepares_and_cleans_a_pinned_allowlist() -> Result<()> {
    let id = BoxId::new("box-0")?;
    let namespace = "test";
    let names = NetworkNames::for_box(namespace, &id);
    let host = PreparedNativeHost::new(&id, &names);
    let controller = NativeLinuxDockerEgressController::new(Arc::new(Resolver));
    let allowlist = tinybox_core::EgressAllowlist::new(["service.test"], [443]);

    let prepared = controller.prepare(&host, namespace, &id, &allowlist).await;
    assert!(
        prepared.is_ok(),
        "{prepared:?}; commands={:?}",
        host.commands()
    );
    let network = prepared?;
    assert_eq!(network.network(), names.network);
    assert_eq!(
        network.host_mappings(),
        [
            ("service.test".to_owned(), IpAddr::from([203, 0, 113, 8])),
            ("service.test".to_owned(), IpAddr::from([203, 0, 113, 9])),
        ]
    );
    controller.cleanup(&host, namespace, &id).await?;

    let commands = host.commands();
    assert!(commands.iter().any(|argv| {
        argv.iter().any(|arg| arg == "-A")
            && argv.iter().any(|arg| arg == "203.0.113.8")
            && argv.iter().any(|arg| arg == "443")
            && argv.iter().any(|arg| arg == "tcp")
            && argv.iter().any(|arg| arg == "ACCEPT")
    }));
    assert!(commands.iter().any(|argv| {
        argv.iter().any(|arg| arg == "DROP") && argv.iter().any(|arg| arg == &names.input_chain)
    }));
    let established_position = commands
        .iter()
        .position(|argv| {
            argv.windows(2)
                .any(|args| args == ["--ctstate", "ESTABLISHED,RELATED"])
        })
        .ok_or_else(|| Error::Backend {
            sandbox: "docker".to_owned(),
            operation: "find established-flow firewall rule",
            message: "rule was not installed".to_owned(),
        })?;
    let forward_drop_position = commands
        .iter()
        .position(|argv| {
            argv.windows(4)
                .any(|args| args == ["-A", &names.forward_chain, "-j", "DROP"])
        })
        .ok_or_else(|| Error::Backend {
            sandbox: "docker".to_owned(),
            operation: "find forward default-drop rule",
            message: "rule was not installed".to_owned(),
        })?;
    assert!(established_position < forward_drop_position);
    assert_input_return_rules(&commands, &names)?;
    assert!(commands.iter().any(|argv| {
        argv.iter().any(|arg| arg == "-D") && argv.iter().any(|arg| arg == "DOCKER-USER")
    }));
    assert!(commands.iter().any(|argv| {
        argv.iter().any(|arg| arg == "rm") && argv.iter().any(|arg| arg == &names.network)
    }));
    assert!(
        commands
            .iter()
            .filter(|argv| argv.iter().any(|arg| arg == "docker"))
            .all(|argv| {
                argv.first().is_some_and(|arg| arg == "docker")
                    && argv.iter().any(|arg| arg == "--host")
                    && argv.iter().any(|arg| arg == "unix:///var/run/docker.sock")
            })
    );
    Ok(())
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn cleanup_reclaims_an_empty_attempt_chain_after_restart() -> Result<()> {
    let id = BoxId::new("box-empty-orphan")?;
    let namespace = "test";
    let names = NetworkNames::for_box(namespace, &id);
    let mut host = PreparedNativeHost::new(&id, &names);
    host.no_matching_hooks = true;
    host.chains
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(("iptables".to_owned(), names.forward_chain.clone()));

    // This host models a fresh process: no attempt-owned in-memory set exists.
    NativeLinuxDockerEgressController::new(Arc::new(Resolver))
        .cleanup(&host, namespace, &id)
        .await?;
    assert!(
        !host
            .chains
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(&("iptables".to_owned(), names.forward_chain.clone()))
    );
    assert!(host.commands().iter().any(|argv| {
        argv.iter().any(|arg| arg == "-X") && argv.iter().any(|arg| arg == &names.forward_chain)
    }));
    Ok(())
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn cleanup_without_network_succeeds_when_no_orphaned_chains_exist() -> Result<()> {
    let id = BoxId::new("box-network-already-absent")?;
    let namespace = "test";
    let names = NetworkNames::for_box(namespace, &id);
    let mut host = PreparedNativeHost::new(&id, &names);
    host.network_inspect_behavior = NetworkInspectBehavior::Absent;
    host.no_matching_hooks = true;

    NativeLinuxDockerEgressController::new(Arc::new(Resolver))
        .cleanup(&host, namespace, &id)
        .await?;

    let commands = host.commands();
    assert!(
        commands
            .iter()
            .filter(|argv| argv.iter().any(|arg| arg == "-S"))
            .count()
            >= 2
    );
    assert!(!commands.iter().any(|argv| {
        argv.iter()
            .any(|arg| matches!(arg.as_str(), "-D" | "-F" | "-X" | "rm"))
    }));
    Ok(())
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn cleanup_ignores_another_boxes_chain_after_its_network_is_absent() -> Result<()> {
    let namespace = "default";
    let removed_box = BoxId::new("box-0")?;
    let remaining_box = BoxId::new("box-1")?;
    let removed_names = NetworkNames::for_box(namespace, &removed_box);
    let remaining_names = NetworkNames::for_box(namespace, &remaining_box);
    let removed_hash = stable_hash(namespace.as_bytes(), removed_box.as_str().as_bytes());
    let remaining_hash = stable_hash(namespace.as_bytes(), remaining_box.as_str().as_bytes());
    assert_eq!(removed_names.forward_chain.len(), 28);
    assert_eq!(
        format!("{removed_hash:016x}").get(..4),
        format!("{remaining_hash:016x}").get(..4),
        "fixture IDs must collide on the previous four-hex chain prefix"
    );

    let mut host = PreparedNativeHost::new(&removed_box, &removed_names);
    host.network_inspect_behavior = NetworkInspectBehavior::Absent;
    host.no_matching_hooks = true;
    host.forward_chain = remaining_names.forward_chain.clone();
    host.chains
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(("iptables".to_owned(), remaining_names.forward_chain));

    NativeLinuxDockerEgressController::new(Arc::new(Resolver))
        .cleanup(&host, namespace, &removed_box)
        .await?;
    Ok(())
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn cleanup_refuses_a_nonempty_unmarked_attempt_chain_after_restart() -> Result<()> {
    let id = BoxId::new("box-nonempty-orphan")?;
    let namespace = "test";
    let names = NetworkNames::for_box(namespace, &id);
    let mut host = PreparedNativeHost::new(&id, &names);
    host.no_matching_hooks = true;
    host.chains
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(("iptables".to_owned(), names.forward_chain.clone()));
    host.chains_with_rules
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(("iptables".to_owned(), names.forward_chain.clone()));

    assert!(
        NativeLinuxDockerEgressController::new(Arc::new(Resolver))
            .cleanup(&host, namespace, &id)
            .await
            .is_err()
    );
    assert!(!host.commands().iter().any(|argv| {
        argv.iter()
            .any(|arg| matches!(arg.as_str(), "-D" | "-F" | "-X"))
    }));
    assert!(
        host.chains
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(&("iptables".to_owned(), names.forward_chain.clone()))
    );
    Ok(())
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn pinned_targets_inside_auto_selected_network_subnets_are_rejected_and_rolled_back()
-> Result<()> {
    for (id_text, address, subnet) in [
        ("box-v4-overlap", "172.28.1.5", "172.28.0.0/16"),
        ("box-v6-overlap", "fd00:1234::42", "fd00:1234::/64"),
    ] {
        let id = BoxId::new(id_text)?;
        let namespace = "test";
        let names = NetworkNames::for_box(namespace, &id);
        let mut host = PreparedNativeHost::new(&id, &names);
        host.network_subnets = format!(r#"[{{"Subnet":"{subnet}"}}]"#);
        let controller = NativeLinuxDockerEgressController::new(Arc::new(Resolver));
        let allowlist = tinybox_core::EgressAllowlist::new([address], [443]);

        assert!(matches!(
            controller.prepare(&host, namespace, &id, &allowlist).await,
            Err(Error::EgressAllowlistUnavailable { .. })
        ));
        let commands = host.commands();
        assert!(commands.iter().any(|argv| {
            argv.iter().any(|arg| arg == "inspect")
                && argv.iter().any(|arg| arg.contains(".IPAM.Config"))
        }));
        assert!(commands.iter().any(|argv| {
            argv.iter().any(|arg| arg == "rm") && argv.iter().any(|arg| arg == &names.network)
        }));
        assert!(!commands.iter().any(|argv| {
            argv.iter()
                .any(|arg| matches!(arg.as_str(), "-N" | "-A" | "-I"))
                && argv
                    .iter()
                    .any(|arg| matches!(arg.as_str(), "iptables" | "ip6tables"))
        }));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn assert_input_return_rules(commands: &[Vec<String>], names: &NetworkNames) -> Result<()> {
    let input_established_position = commands
        .iter()
        .position(|argv| {
            argv.iter().any(|arg| arg == "iptables")
                && argv
                    .windows(4)
                    .any(|args| args == ["-A", &names.input_chain, "-m", "conntrack"])
                && argv
                    .windows(2)
                    .any(|args| args == ["--ctstate", "ESTABLISHED,RELATED"])
        })
        .ok_or_else(|| Error::Backend {
            sandbox: "docker".to_owned(),
            operation: "find established INPUT return rule",
            message: "rule was not installed".to_owned(),
        })?;
    let ipv4_input_drop_position = commands
        .iter()
        .position(|argv| {
            argv.iter().any(|arg| arg == "iptables")
                && argv
                    .windows(4)
                    .any(|args| args == ["-A", &names.input_chain, "-j", "DROP"])
        })
        .ok_or_else(|| Error::Backend {
            sandbox: "docker".to_owned(),
            operation: "find IPv4 INPUT default-drop rule",
            message: "rule was not installed".to_owned(),
        })?;
    assert!(input_established_position < ipv4_input_drop_position);
    let neighbor_solicitation_position = commands
        .iter()
        .position(|argv| {
            argv.iter().any(|arg| arg == "ip6tables")
                && argv.iter().any(|arg| arg == "neighbor-solicitation")
        })
        .ok_or_else(|| Error::Backend {
            sandbox: "docker".to_owned(),
            operation: "find IPv6 neighbor-discovery rule",
            message: "rule was not installed".to_owned(),
        })?;
    let neighbor_advertisement_position = commands
        .iter()
        .position(|argv| {
            argv.iter().any(|arg| arg == "ip6tables")
                && argv.iter().any(|arg| arg == "neighbor-advertisement")
        })
        .ok_or_else(|| Error::Backend {
            sandbox: "docker".to_owned(),
            operation: "find IPv6 neighbor-advertisement rule",
            message: "rule was not installed".to_owned(),
        })?;
    let input_drop_position = commands
        .iter()
        .position(|argv| {
            argv.iter().any(|arg| arg == "ip6tables")
                && argv
                    .windows(4)
                    .any(|args| args == ["-A", &names.input_chain, "-j", "DROP"])
        })
        .ok_or_else(|| Error::Backend {
            sandbox: "docker".to_owned(),
            operation: "find INPUT default-drop rule",
            message: "rule was not installed".to_owned(),
        })?;
    let ipv6_input_established_position = commands
        .iter()
        .position(|argv| {
            argv.iter().any(|arg| arg == "ip6tables")
                && argv
                    .windows(4)
                    .any(|args| args == ["-A", &names.input_chain, "-m", "conntrack"])
                && argv
                    .windows(2)
                    .any(|args| args == ["--ctstate", "ESTABLISHED,RELATED"])
        })
        .ok_or_else(|| Error::Backend {
            sandbox: "docker".to_owned(),
            operation: "find IPv6 established INPUT return rule",
            message: "rule was not installed".to_owned(),
        })?;
    assert!(neighbor_solicitation_position < ipv6_input_established_position);
    assert!(neighbor_advertisement_position < ipv6_input_established_position);
    assert!(ipv6_input_established_position < input_drop_position);
    Ok(())
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn native_controller_maps_ipv4_mapped_answers_as_ipv4() -> Result<()> {
    let id = BoxId::new("box-mapped")?;
    let namespace = "test";
    let names = NetworkNames::for_box(namespace, &id);
    let host = PreparedNativeHost::new(&id, &names);
    let controller = NativeLinuxDockerEgressController::new(Arc::new(MappedIpv4Resolver));
    let allowlist = tinybox_core::EgressAllowlist::new(["service.test"], [443]);

    let prepared = controller
        .prepare(&host, namespace, &id, &allowlist)
        .await?;

    assert_eq!(
        prepared.host_mappings(),
        [("service.test".to_owned(), IpAddr::from([203, 0, 113, 11]))]
    );
    let commands = host.commands();
    assert!(commands.iter().any(|argv| {
        argv.iter().any(|part| part == "iptables")
            && argv.iter().any(|part| part == "203.0.113.11")
            && argv.iter().any(|part| part == "ACCEPT")
    }));
    assert!(!commands.iter().any(|argv| {
        argv.iter().any(|part| part == "ip6tables")
            && argv.iter().any(|part| part.contains("203.0.113.11"))
    }));
    controller.cleanup(&host, namespace, &id).await?;
    Ok(())
}

#[tokio::test]
async fn cleanup_refuses_a_different_network_owner_before_firewall_mutation() -> Result<()> {
    let id = BoxId::new("box-foreign-owner")?;
    let namespace = "test";
    let names = NetworkNames::for_box(namespace, &id);
    let mut host = PreparedNativeHost::new(&id, &names);
    host.network_owner = "another-box".to_owned();
    let controller = NativeLinuxDockerEgressController::new(Arc::new(Resolver));

    assert!(controller.cleanup(&host, namespace, &id).await.is_err());

    assert!(!host.commands().iter().any(|argv| {
        argv.iter()
            .any(|part| part == "iptables" || part == "ip6tables")
            && argv
                .iter()
                .any(|part| part == "-D" || part == "-F" || part == "-X")
    }));
    Ok(())
}

#[tokio::test]
async fn cleanup_refuses_a_network_scope_hash_collision_before_firewall_mutation() -> Result<()> {
    let id = BoxId::new("box-scope-collision")?;
    let namespace = "test";
    let names = NetworkNames::for_box(namespace, &id);
    let mut host = PreparedNativeHost::new(&id, &names);
    host.network_scope = "different-full-hash".to_owned();
    let controller = NativeLinuxDockerEgressController::new(Arc::new(Resolver));

    assert!(controller.cleanup(&host, namespace, &id).await.is_err());

    assert!(!host.commands().iter().any(|argv| {
        argv.iter()
            .any(|part| part == "iptables" || part == "ip6tables")
            && argv
                .iter()
                .any(|part| part == "-D" || part == "-F" || part == "-X")
    }));
    Ok(())
}

#[tokio::test]
async fn cleanup_refuses_firewall_chains_with_another_owner_marker() -> Result<()> {
    let id = BoxId::new("box-chain-collision")?;
    let namespace = "test";
    let names = NetworkNames::for_box(namespace, &id);
    let mut host = PreparedNativeHost::new(&id, &names);
    host.chain_owner_token = "different-full-hash".to_owned();
    host.chains
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .extend([
            ("iptables".to_owned(), names.forward_chain.clone()),
            ("iptables".to_owned(), names.input_chain.clone()),
        ]);
    host.chains_with_rules
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .extend([
            ("iptables".to_owned(), names.forward_chain.clone()),
            ("iptables".to_owned(), names.input_chain.clone()),
        ]);
    host.marked_chains
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .extend([
            ("iptables".to_owned(), names.forward_chain.clone()),
            ("iptables".to_owned(), names.input_chain.clone()),
        ]);
    let controller = NativeLinuxDockerEgressController::new(Arc::new(Resolver));

    assert!(controller.cleanup(&host, namespace, &id).await.is_err());

    assert!(!host.commands().iter().any(|argv| {
        argv.iter()
            .any(|part| part == "iptables" || part == "ip6tables")
            && argv
                .iter()
                .any(|part| part == "-D" || part == "-F" || part == "-X")
    }));
    Ok(())
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn cleanup_restores_owner_marker_when_chain_delete_fails_after_flush() -> Result<()> {
    let id = BoxId::new("box-delete-retry")?;
    let namespace = "test";
    let names = NetworkNames::for_box(namespace, &id);
    let host = PreparedNativeHost::new(&id, &names);
    *host
        .fail_chain_delete_once
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
    host.chains
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(("iptables".to_owned(), names.forward_chain.clone()));
    host.marked_chains
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(("iptables".to_owned(), names.forward_chain.clone()));
    let controller = NativeLinuxDockerEgressController::new(Arc::new(Resolver));

    assert!(controller.cleanup(&host, namespace, &id).await.is_err());
    assert!(
        host.marked_chains
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(&("iptables".to_owned(), names.forward_chain.clone()))
    );
    controller.cleanup(&host, namespace, &id).await?;
    assert!(
        !host
            .chains
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(&("iptables".to_owned(), names.forward_chain.clone()))
    );
    Ok(())
}

#[test]
fn deny_rules_block_metadata_without_disabling_other_link_local_destinations() {
    let ipv4 = deny_rules(false);
    let ipv6 = deny_rules(true);
    let has_destination = |rules: &[Vec<String>], destination: &str| {
        rules
            .iter()
            .any(|rule| rule.windows(2).any(|pair| pair == ["-d", destination]))
    };

    assert!(has_destination(&ipv4, "169.254.169.254/32"));
    assert!(has_destination(&ipv4, "169.254.170.2/32"));
    assert!(!has_destination(&ipv4, "169.254.0.0/16"));
    assert!(has_destination(&ipv6, "fd00:ec2::254/128"));
    assert!(!has_destination(&ipv6, "fe80::/10"));
}

#[test]
fn firewall_owner_token_uses_unambiguous_sha256_identity() {
    let left = scope_token("ab", "c");
    let right = scope_token("a", "bc");

    assert_eq!(left.len(), 64);
    assert_ne!(left, right);
    assert_eq!(left, scope_token("ab", "c"));
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn network_name_conflict_does_not_clean_an_existing_owners_firewall() -> Result<()> {
    let id = BoxId::new("box-0")?;
    let namespace = "test";
    let names = NetworkNames::for_box(namespace, &id);
    let mut host = PreparedNativeHost::new(&id, &names);
    host.network_create_behavior = NetworkCreateBehavior::CommandFailure;
    host.network_inspect_behavior = NetworkInspectBehavior::Foreign;
    let controller = NativeLinuxDockerEgressController::new(Arc::new(Resolver));
    let allowlist = tinybox_core::EgressAllowlist::new(["service.test"], [443]);

    assert!(matches!(
        controller.prepare(&host, namespace, &id, &allowlist).await,
        Err(Error::Backend {
            operation: "configure egress filtering",
            ..
        })
    ));
    assert!(host.commands().iter().all(|argv| {
        !argv
            .iter()
            .any(|arg| matches!(arg.as_str(), "-D" | "-F" | "-X"))
    }));
    assert!(
        !host
            .commands()
            .iter()
            .any(|argv| argv.iter().any(|arg| arg == "inspect"))
    );
    assert!(
        !host
            .commands()
            .iter()
            .any(|argv| { argv.iter().any(|arg| arg == "rm") })
    );
    Ok(())
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn network_create_conflict_does_not_remove_an_existing_same_owner_network() -> Result<()> {
    let id = BoxId::new("box-stale-owned-network")?;
    let namespace = "test";
    let names = NetworkNames::for_box(namespace, &id);
    let mut host = PreparedNativeHost::new(&id, &names);
    host.network_create_behavior = NetworkCreateBehavior::CommandFailure;
    let controller = NativeLinuxDockerEgressController::new(Arc::new(Resolver));
    let allowlist = tinybox_core::EgressAllowlist::new(["service.test"], [443]);

    assert!(matches!(
        controller.prepare(&host, namespace, &id, &allowlist).await,
        Err(Error::Backend {
            operation: "configure egress filtering",
            ref message,
            ..
        }) if message.contains("network name already exists")
    ));
    assert!(!host.commands().iter().any(|argv| {
        argv.iter().any(|arg| arg == "rm")
            || (argv.iter().any(|arg| arg == "inspect")
                && argv.iter().any(|arg| arg.contains("{{.Id}}")))
    }));
    assert!(!host.commands().iter().any(|argv| {
        argv.iter()
            .any(|arg| matches!(arg.as_str(), "-A" | "-D" | "-F" | "-X"))
    }));
    Ok(())
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn nonzero_network_create_reconciles_a_current_attempt_side_effect() -> Result<()> {
    let id = BoxId::new("box-nonzero-create-side-effect")?;
    let namespace = "test";
    let names = NetworkNames::for_box(namespace, &id);
    let mut host = PreparedNativeHost::new(&id, &names);
    host.network_create_behavior = NetworkCreateBehavior::CommandFailureAfterSideEffect;
    let controller = NativeLinuxDockerEgressController::new(Arc::new(Resolver));
    let allowlist = tinybox_core::EgressAllowlist::new(["service.test"], [443]);

    assert!(matches!(
        controller.prepare(&host, namespace, &id, &allowlist).await,
        Err(Error::Backend {
            operation: "configure egress filtering",
            ref message,
            ..
        }) if message.contains("simulated lost command response after network creation")
    ));
    let commands = host.commands();
    assert!(commands.iter().any(|argv| {
        argv.iter().any(|arg| arg == "inspect") && argv.iter().any(|arg| arg.contains("{{.Id}}"))
    }));
    assert!(
        commands
            .iter()
            .any(|argv| argv.iter().any(|arg| arg == "rm"))
    );
    assert!(!commands.iter().any(|argv| {
        argv.iter()
            .any(|arg| matches!(arg.as_str(), "-A" | "-D" | "-F" | "-X"))
    }));
    Ok(())
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn empty_successful_network_create_rolls_back_the_owned_network() -> Result<()> {
    let id = BoxId::new("box-0")?;
    let namespace = "test";
    let names = NetworkNames::for_box(namespace, &id);
    let mut host = PreparedNativeHost::new(&id, &names);
    host.empty_network_create = true;
    let controller = NativeLinuxDockerEgressController::new(Arc::new(Resolver));
    let allowlist = tinybox_core::EgressAllowlist::new(["service.test"], [443]);

    assert!(matches!(
        controller.prepare(&host, namespace, &id, &allowlist).await,
        Err(Error::EgressAllowlistUnavailable { .. })
    ));
    assert!(host.commands().iter().any(|argv| {
        argv.iter().any(|arg| arg == "rm") && argv.iter().any(|arg| arg == &names.network)
    }));
    Ok(())
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn owner_marker_install_failure_rolls_back_created_chain_and_network() -> Result<()> {
    let id = BoxId::new("box-marker-failure")?;
    let namespace = "test";
    let names = NetworkNames::for_box(namespace, &id);
    let mut host = PreparedNativeHost::new(&id, &names);
    host.fail_chain_marker = true;
    let controller = NativeLinuxDockerEgressController::new(Arc::new(Resolver));
    let allowlist = tinybox_core::EgressAllowlist::new(["service.test"], [443]);

    let result = controller.prepare(&host, namespace, &id, &allowlist).await;

    assert!(result.is_err());
    let commands = host.commands();
    assert!(commands.iter().any(|argv| {
        argv.iter().any(|arg| arg == "rm") && argv.iter().any(|arg| arg == &names.network)
    }));
    assert!(
        host.chains
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_empty()
    );
    Ok(())
}

#[cfg(not(target_os = "linux"))]
#[tokio::test]
async fn native_controller_refuses_non_linux_before_host_commands() -> Result<()> {
    let id = BoxId::new("box-non-linux")?;
    let names = NetworkNames::for_box("test", &id);
    let host = PreparedNativeHost::new(&id, &names);
    let controller = NativeLinuxDockerEgressController::new(Arc::new(Resolver));

    assert!(matches!(
        controller.validate_host(&host).await,
        Err(Error::EgressAllowlistUnavailable { .. })
    ));
    assert!(host.commands().is_empty());
    Ok(())
}

#[tokio::test]
async fn missing_forward_hook_refuses_native_egress_before_resource_creation() {
    for firewall in ["iptables", "ip6tables"] {
        let host = FakeNativeHost::new(firewall);
        let controller = NativeLinuxDockerEgressController::new(Arc::new(Resolver));

        assert!(matches!(
            controller.validate_host(&host).await,
            Err(Error::EgressAllowlistUnavailable { .. })
        ));
        assert!(
            host.commands()
                .iter()
                .all(|argv| !argv.contains(&"create".to_owned()))
        );
    }
}
