//! Per-box Docker network filtering for explicitly supported native Linux hosts.
//!
//! The controller installs a host firewall before Docker starts the box. It
//! consumes pinned resolver answers and does not use proxy environment
//! variables as an enforcement boundary.

use std::{collections::BTreeSet, fmt::Debug, net::IpAddr, sync::Arc};

use async_trait::async_trait;
use ipnet::IpNet;
use sha2::{Digest, Sha256};
use tinybox_core::{
    BoxId, EgressAllowlist, Error, ExecOutput, ExecRequest, Host, HostExecutionLocation, Result,
};
#[cfg(not(test))]
use uuid::Uuid;

use crate::{EgressResolver, PinnedEgressPlan, plan_egress_allowlist};

const DOCKER_SOCKET: &str = "unix:///var/run/docker.sock";
const OWNER_LABEL: &str = "ai.tinyhumans.tinybox.egress.owner";
const SCOPE_LABEL: &str = "ai.tinyhumans.tinybox.egress.scope";
const ATTEMPT_LABEL: &str = "ai.tinyhumans.tinybox.egress.attempt";
const ALLOWLIST_PROTOCOLS: [&str; 1] = ["tcp"];
const HEX: &[u8; 16] = b"0123456789abcdef";

/// A controller that installs and removes a per-box egress filter.
///
/// Implementations are trusted security components. A controller must verify
/// that it acts on the same daemon and host that run the box, install a
/// default-drop filter before returning from [`prepare`](Self::prepare), and
/// make [`cleanup`](Self::cleanup) idempotent. `DockerSandbox` uses
/// [`docker_argv`](Self::docker_argv) for every Docker command while the
/// controller is installed, so lifecycle operations address the same daemon.
#[async_trait]
pub trait DockerEgressController: Debug + Send + Sync {
    /// Verify the execution location and required daemon/filter capability.
    ///
    /// # Errors
    ///
    /// Returns an error when the host cannot be verified as safe for egress
    /// enforcement.
    async fn validate_host(&self, _host: &dyn Host) -> Result<()> {
        Ok(())
    }

    /// Resolve, pin, and prepare a filtered network for this box.
    ///
    /// Implementations must not start the workload. The returned network name
    /// is supplied to `docker run` only after this method succeeds. On error,
    /// the controller must roll back every resource it created. If rollback
    /// fails, it must return [`Error::EgressRollbackFailed`], allowing the
    /// sandbox to retain the box record for a later cleanup retry.
    ///
    /// # Errors
    ///
    /// Returns an error if planning, host verification, network creation, or
    /// firewall setup fails. Returns [`Error::EgressRollbackFailed`] when
    /// cleanup of partially-created resources also fails.
    async fn prepare(
        &self,
        host: &dyn Host,
        namespace: &str,
        id: &BoxId,
        allowlist: &EgressAllowlist,
    ) -> Result<PreparedEgressNetwork>;

    /// Remove this box's filter and network after its container has stopped.
    ///
    /// # Errors
    ///
    /// Returns an error if ownership cannot be verified or cleanup fails.
    async fn cleanup(&self, host: &dyn Host, namespace: &str, id: &BoxId) -> Result<()>;

    /// Bind a Docker CLI command to the daemon this controller verifies.
    fn docker_argv(&self, argv: Vec<String>) -> Vec<String>;

    /// Whether Docker commands must run on a host explicitly identified as local.
    fn requires_local_docker_host(&self) -> bool {
        false
    }
}

/// A firewall-protected network and the hostname mappings pinned for it.
///
/// The sandbox installs these mappings in `/etc/hosts` and points the
/// container's upstream resolver at its own loopback, so Docker's embedded
/// resolver cannot forward arbitrary DNS queries through the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedEgressNetwork {
    network: String,
    host_mappings: Vec<(String, IpAddr)>,
}

impl PreparedEgressNetwork {
    /// Build a network result for a trusted egress controller.
    #[must_use]
    pub fn new(network: String, host_mappings: Vec<(String, IpAddr)>) -> Self {
        Self {
            network,
            host_mappings,
        }
    }

    /// Docker network name to attach to the workload.
    #[must_use]
    pub fn network(&self) -> &str {
        &self.network
    }

    /// Pinned `/etc/hosts` entries used instead of upstream DNS.
    #[must_use]
    pub fn host_mappings(&self) -> &[(String, IpAddr)] {
        &self.host_mappings
    }
}

/// Native Linux Engine support using the local rootful Docker socket and
/// `iptables`/`ip6tables` `DOCKER-USER` chains.
///
/// The default [`DockerSandbox`](crate::DockerSandbox) has no controller and
/// continues to refuse allowlists. Install this controller explicitly only on
/// a local native Linux Docker Engine with non-interactive firewall privilege.
/// Docker Desktop, SSH/remote hosts, rootless Docker, Windows containers, and
/// hosts without the expected firewall chains are refused.
/// The controller also inspects Docker-assigned IPAM subnets and refuses a
/// pinned destination contained in one, avoiding on-link routing around the
/// intended gateway path.
#[derive(Debug)]
pub struct NativeLinuxDockerEgressController {
    resolver: Arc<dyn EgressResolver>,
}

impl NativeLinuxDockerEgressController {
    /// Use `resolver` to resolve allowlist names before network creation.
    #[must_use]
    pub fn new(resolver: Arc<dyn EgressResolver>) -> Self {
        Self { resolver }
    }

    /// Return a controller only when `host` can enforce an allowlist.
    ///
    /// Runs the same checks as [`validate_host`](DockerEgressController::validate_host):
    /// a local native rootful Linux Engine, root firewall chains reachable
    /// through non-interactive `sudo`, and Docker's `FORWARD` hook in first
    /// place. Install the returned controller only on success: an installed
    /// controller binds every Docker command to the local rootful daemon.
    ///
    /// # Errors
    ///
    /// Returns [`Error::EgressAllowlistUnavailable`] naming the first check
    /// the host failed, or the host's own error if a probe could not run.
    pub async fn detect(host: &dyn Host, resolver: Arc<dyn EgressResolver>) -> Result<Self> {
        let controller = Self::new(resolver);
        controller.validate_host(host).await?;
        Ok(controller)
    }
}

#[cfg(test)]
#[path = "egress_enforcement_tests.rs"]
mod tests;

#[async_trait]
impl DockerEgressController for NativeLinuxDockerEgressController {
    async fn validate_host(&self, host: &dyn Host) -> Result<()> {
        ensure_supported_host(host)?;
        ensure_linux_target()?;
        verify_engine_and_firewall(host).await
    }

    async fn prepare(
        &self,
        host: &dyn Host,
        namespace: &str,
        id: &BoxId,
        allowlist: &EgressAllowlist,
    ) -> Result<PreparedEgressNetwork> {
        ensure_supported_host(host)?;
        ensure_linux_target()?;
        verify_engine_and_firewall(host).await?;

        // Resolve before creating any Docker resources. Every installed rule is
        // based on this one pinned answer set; workload DNS is not trusted for
        // egress decisions.
        let plan = plan_egress_allowlist(allowlist, self.resolver.as_ref())?;
        let names = NetworkNames::for_box(namespace, id);
        let create_network = docker_request(
            host,
            force_local_rootful_docker(vec![
                "docker".into(),
                "network".into(),
                "create".into(),
                "--driver".into(),
                "bridge".into(),
                "--ipv6".into(),
                "--opt".into(),
                format!("com.docker.network.bridge.name={}", names.bridge),
                "--label".into(),
                format!("{OWNER_LABEL}={id}"),
                "--label".into(),
                format!("{SCOPE_LABEL}={}", names.owner_token),
                "--label".into(),
                format!("{ATTEMPT_LABEL}={}", names.attempt_token),
                names.network.clone(),
            ]),
        )
        .await;
        let network = match create_network {
            Ok(output) if output.succeeded() => output.stdout_lossy().trim().to_owned(),
            Ok(output) => {
                let error = Error::Backend {
                    sandbox: "docker".to_owned(),
                    operation: "configure egress filtering",
                    message: output.stderr_lossy().trim().to_owned(),
                };
                if output.stderr_lossy().contains("already exists") {
                    return Err(error);
                }
                return Err(reconcile_failed_network_create(host, &names, id, error).await);
            }
            Err(error) => {
                return Err(reconcile_failed_network_create(host, &names, id, error).await);
            }
        };
        if network.is_empty() {
            let error = unsupported("Docker did not confirm the egress network");
            return match cleanup_native_with_attempt(host, namespace, id, &BTreeSet::new(), false)
                .await
            {
                Ok(()) => Err(error),
                Err(cleanup_error) => Err(Error::EgressRollbackFailed {
                    sandbox: "docker".to_owned(),
                    message: format!("{error}; cleanup failed: {cleanup_error}"),
                }),
            };
        }

        let mut attempt_owned_chains = BTreeSet::new();
        let setup = async {
            verify_created_network(host, &names, id).await?;
            verify_targets_outside_network_subnets(host, &names, &plan).await?;
            verify_created_bridge_link(host, &names).await?;
            install_firewall(host, &names, &plan, &mut attempt_owned_chains).await
        }
        .await;
        if let Err(error) = setup {
            let cleanup =
                cleanup_native_with_attempt(host, namespace, id, &attempt_owned_chains, false)
                    .await;
            return match cleanup {
                Ok(()) => Err(error),
                Err(cleanup_error) => Err(Error::EgressRollbackFailed {
                    sandbox: "docker".to_owned(),
                    message: format!("{error}; cleanup failed: {cleanup_error}"),
                }),
            };
        }

        let host_mappings = plan
            .targets()
            .iter()
            .flat_map(|target| {
                let host = target.host();
                if host.parse::<IpAddr>().is_ok() {
                    return Vec::new();
                }
                let unqualified = host.trim_end_matches('.');
                let mut names = vec![(host.to_owned(), target.address())];
                if unqualified != host {
                    names.push((unqualified.to_owned(), target.address()));
                }
                names
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        Ok(PreparedEgressNetwork::new(names.network, host_mappings))
    }

    async fn cleanup(&self, host: &dyn Host, namespace: &str, id: &BoxId) -> Result<()> {
        ensure_supported_host(host)?;
        ensure_linux_target()?;
        verify_engine_and_firewall(host).await?;
        cleanup_native(host, namespace, id).await
    }

    fn docker_argv(&self, argv: Vec<String>) -> Vec<String> {
        force_local_rootful_docker(argv)
    }

    fn requires_local_docker_host(&self) -> bool {
        true
    }
}

#[derive(Debug)]
struct NetworkNames {
    network: String,
    bridge: String,
    forward_chain: String,
    input_chain: String,
    owner_token: String,
    attempt_token: String,
    chain_prefix: String,
    chain_owner_token: String,
}

impl NetworkNames {
    fn for_box(namespace: &str, id: &BoxId) -> Self {
        let attempt_token = fresh_attempt_token(namespace, id);
        Self::for_attempt(namespace, id, &attempt_token)
    }

    fn for_attempt(namespace: &str, id: &BoxId, attempt_token: &str) -> Self {
        let hash = stable_hash(namespace.as_bytes(), id.as_str().as_bytes());
        let short = format!("{hash:016x}");
        let owner_token = scope_token(namespace, id.as_str());
        // iptables chain names allow at most 28 visible characters. Keep a
        // 48-bit box identity in the orphan-scan prefix and a 48-bit attempt
        // suffix so one box cannot make another box's chain look like an orphan.
        let chain_prefix = format!("TBX{}", &owner_token[..12]);
        let chain_token = &attempt_token[..12];
        Self {
            network: format!("tinybox-egress-{}", &short[..12]),
            // Linux interface names are limited to IFNAMSIZ - 1 (15 bytes).
            bridge: format!("tbx{}", &short[..12]),
            forward_chain: format!("{chain_prefix}{chain_token}F"),
            input_chain: format!("{chain_prefix}{chain_token}I"),
            owner_token,
            attempt_token: attempt_token.to_owned(),
            chain_prefix,
            chain_owner_token: chain_owner_token(namespace, id.as_str(), attempt_token),
        }
    }
}

fn fresh_attempt_token(namespace: &str, id: &BoxId) -> String {
    #[cfg(test)]
    {
        scope_token(namespace, id.as_str())[..32].to_owned()
    }
    #[cfg(not(test))]
    {
        let _ = (namespace, id);
        Uuid::new_v4().simple().to_string()
    }
}

fn chain_owner_token(namespace: &str, id: &str, attempt: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"tinybox-egress-chain-owner-v1\0");
    for value in [namespace, id, attempt] {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value.as_bytes());
    }
    let digest = hasher.finalize();
    let mut token = String::with_capacity(64);
    for byte in digest {
        token.push(char::from(HEX[usize::from(byte >> 4)]));
        token.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    token
}

fn valid_attempt_token(attempt: &str) -> bool {
    attempt.len() == 32 && attempt.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn scope_token(namespace: &str, id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update((namespace.len() as u64).to_be_bytes());
    hasher.update(namespace.as_bytes());
    hasher.update((id.len() as u64).to_be_bytes());
    hasher.update(id.as_bytes());
    let digest = hasher.finalize();
    let mut token = String::with_capacity(64);
    for byte in digest {
        token.push(char::from(HEX[usize::from(byte >> 4)]));
        token.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    token
}

fn stable_hash(namespace: &[u8], id: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in namespace.iter().chain([0].iter()).chain(id) {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn ensure_supported_host(host: &dyn Host) -> Result<()> {
    if host.execution_location() != HostExecutionLocation::Local {
        return Err(unsupported(
            "egress filtering requires an explicitly local execution host",
        ));
    }
    Ok(())
}

fn ensure_linux_target() -> Result<()> {
    if cfg!(target_os = "linux") {
        Ok(())
    } else {
        Err(unsupported(
            "native Docker egress filtering is available only on Linux",
        ))
    }
}

fn unsupported(reason: &str) -> Error {
    Error::EgressAllowlistUnavailable {
        sandbox: "docker".to_owned(),
        reason: reason.to_owned(),
    }
}

async fn verify_engine_and_firewall(host: &dyn Host) -> Result<()> {
    ensure_supported_host(host)?;
    ensure_linux_target()?;

    let info = docker_output(
        host,
        vec![
            "docker".into(),
            "info".into(),
            "--format".into(),
            "{{.OSType}}|{{.OperatingSystem}}|{{json .SecurityOptions}}".into(),
        ],
    )
    .await?;
    let mut fields = info.splitn(3, '|');
    let os_type = fields.next().unwrap_or_default().trim();
    let operating_system = fields.next().unwrap_or_default().trim();
    let security = fields.next().unwrap_or_default().to_ascii_lowercase();
    if os_type != "linux"
        || operating_system.is_empty()
        || operating_system.to_ascii_lowercase().contains("desktop")
        || security.contains("rootless")
    {
        return Err(unsupported(
            "Docker daemon is not a native rootful Linux Engine",
        ));
    }

    for firewall in ["iptables", "ip6tables"] {
        for chain in ["DOCKER-USER", "INPUT"] {
            let output = host
                .run(&ExecRequest::new([
                    "sudo", "-n", firewall, "-w", "5", "-S", chain,
                ]))
                .await?;
            if !output.succeeded() {
                return Err(unsupported("required root firewall chains are unavailable"));
            }
        }
        let forward = firewall_output(host, firewall, ["-S", "FORWARD"]).await?;
        let first_rule = forward.lines().find(|line| line.starts_with("-A FORWARD "));
        if first_rule != Some("-A FORWARD -j DOCKER-USER") {
            return Err(unsupported(
                "Docker egress firewall hook is missing or ordered after another FORWARD rule",
            ));
        }
    }
    Ok(())
}

async fn verify_created_network(host: &dyn Host, names: &NetworkNames, id: &BoxId) -> Result<()> {
    let output = docker_output(
        host,
        vec![
            "docker".into(),
            "network".into(),
            "inspect".into(),
            "--format".into(),
            format!("{{{{.Driver}}}}|{{{{.EnableIPv6}}}}|{{{{index .Options \"com.docker.network.bridge.name\"}}}}|{{{{index .Labels \"{OWNER_LABEL}\"}}}}|{{{{index .Labels \"{SCOPE_LABEL}\"}}}}|{{{{index .Labels \"{ATTEMPT_LABEL}\"}}}}"),
            names.network.clone(),
        ],
    )
    .await?;
    let expected = format!(
        "bridge|true|{}|{id}|{}|{}",
        names.bridge, names.owner_token, names.attempt_token
    );
    if output != expected {
        return Err(unsupported(
            "Docker egress network did not match its verified configuration",
        ));
    }
    Ok(())
}

async fn verify_targets_outside_network_subnets(
    host: &dyn Host,
    names: &NetworkNames,
    plan: &PinnedEgressPlan,
) -> Result<()> {
    let output = docker_output(
        host,
        vec![
            "docker".into(),
            "network".into(),
            "inspect".into(),
            "--format".into(),
            "{{json .IPAM.Config}}".into(),
            names.network.clone(),
        ],
    )
    .await?;
    let configs = serde_json::from_str::<Vec<serde_json::Value>>(&output)
        .map_err(|_| unsupported("Docker egress network IPAM configuration is invalid"))?;
    if configs.is_empty() {
        return Err(unsupported(
            "Docker egress network has no inspectable IPAM subnets",
        ));
    }

    let subnets = configs
        .iter()
        .map(|config| {
            config
                .get("Subnet")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| unsupported("Docker egress network subnet is missing"))?
                .parse::<IpNet>()
                .map_err(|_| unsupported("Docker egress network subnet is invalid"))
        })
        .collect::<Result<Vec<_>>>()?;
    if plan.targets().iter().any(|target| {
        subnets
            .iter()
            .any(|subnet| subnet.contains(&target.address()))
    }) {
        return Err(unsupported(
            "an egress destination overlaps the Docker network subnet",
        ));
    }
    Ok(())
}

async fn verify_created_bridge_link(host: &dyn Host, names: &NetworkNames) -> Result<()> {
    let output = host
        .run(&ExecRequest::new([
            "ip",
            "-o",
            "link",
            "show",
            "dev",
            &names.bridge,
        ]))
        .await
        .map_err(|_| unsupported("Docker bridge is not visible in the local network namespace"))?;
    let interface_exists = output.succeeded()
        && output.stdout_lossy().lines().any(|line| {
            line.split_whitespace()
                .nth(1)
                .is_some_and(|name| name.trim_end_matches(':') == names.bridge)
        });
    if !interface_exists {
        return Err(unsupported(
            "Docker bridge is not visible in the local network namespace",
        ));
    }
    Ok(())
}

async fn install_firewall(
    host: &dyn Host,
    names: &NetworkNames,
    plan: &PinnedEgressPlan,
    attempt_owned_chains: &mut BTreeSet<(String, String)>,
) -> Result<()> {
    install_family(host, "iptables", names, plan, false, attempt_owned_chains).await?;
    install_family(host, "ip6tables", names, plan, true, attempt_owned_chains).await?;
    verify_hook(
        host,
        "iptables",
        "DOCKER-USER",
        &names.bridge,
        &names.forward_chain,
    )
    .await?;
    verify_hook(host, "iptables", "INPUT", &names.bridge, &names.input_chain).await?;
    verify_hook(
        host,
        "ip6tables",
        "DOCKER-USER",
        &names.bridge,
        &names.forward_chain,
    )
    .await?;
    verify_hook(
        host,
        "ip6tables",
        "INPUT",
        &names.bridge,
        &names.input_chain,
    )
    .await?;
    Ok(())
}

#[allow(clippy::too_many_lines)] // Preserve the ordered default-drop rule setup as one unit.
async fn install_family(
    host: &dyn Host,
    firewall: &str,
    names: &NetworkNames,
    plan: &PinnedEgressPlan,
    ipv6: bool,
    attempt_owned_chains: &mut BTreeSet<(String, String)>,
) -> Result<()> {
    let existing = firewall_output(host, firewall, ["-S"]).await?;
    if existing.contains(&names.forward_chain) || existing.contains(&names.input_chain) {
        return Err(unsupported("a stale egress firewall chain already exists"));
    }

    for chain in [&names.forward_chain, &names.input_chain] {
        firewall_success(host, firewall, ["-N", chain]).await?;
        attempt_owned_chains.insert((firewall.to_owned(), chain.clone()));
        append_chain_owner_marker(host, firewall, chain, &names.chain_owner_token, ipv6).await?;
    }
    for rule in deny_rules(ipv6) {
        let mut command = vec!["-A".to_owned(), names.forward_chain.clone()];
        command.extend(rule);
        firewall_success(host, firewall, command.iter().map(String::as_str)).await?;
    }
    if ipv6 {
        // Neighbor Discovery needs both Solicitation and Advertisement to
        // resolve and refresh bridge peers. Permit these control messages;
        // new host-bound traffic remains dropped.
        for icmpv6_type in ["neighbor-solicitation", "neighbor-advertisement"] {
            firewall_success(
                host,
                firewall,
                [
                    "-A",
                    &names.input_chain,
                    "-p",
                    "ipv6-icmp",
                    "--icmpv6-type",
                    icmpv6_type,
                    "-j",
                    "ACCEPT",
                ],
            )
            .await?;
        }
    }
    install_pinned_destinations(host, firewall, names, plan, ipv6).await?;
    firewall_success(
        host,
        firewall,
        [
            "-A",
            &names.forward_chain,
            "-m",
            "conntrack",
            "--ctstate",
            "ESTABLISHED,RELATED",
            "-j",
            "ACCEPT",
        ],
    )
    .await?;
    firewall_success(host, firewall, ["-A", &names.forward_chain, "-j", "DROP"]).await?;
    // Permit only return traffic for host-initiated connections, such as
    // responses to a published port. New bridge-to-host connections remain
    // blocked regardless of the allowlist.
    firewall_success(
        host,
        firewall,
        [
            "-A",
            &names.input_chain,
            "-m",
            "conntrack",
            "--ctstate",
            "ESTABLISHED,RELATED",
            "-j",
            "ACCEPT",
        ],
    )
    .await?;
    firewall_success(host, firewall, ["-A", &names.input_chain, "-j", "DROP"]).await?;

    firewall_success(
        host,
        firewall,
        [
            "-I",
            "DOCKER-USER",
            "1",
            "-i",
            &names.bridge,
            "-j",
            &names.forward_chain,
        ],
    )
    .await?;
    firewall_success(
        host,
        firewall,
        [
            "-I",
            "INPUT",
            "1",
            "-i",
            &names.bridge,
            "-j",
            &names.input_chain,
        ],
    )
    .await?;

    // Confirm both custom chains contain the final drop before allowing Docker
    // to attach an image entrypoint to the network.
    for chain in [&names.forward_chain, &names.input_chain] {
        let rules = firewall_output(host, firewall, ["-S", chain]).await?;
        let chain_prefix = format!("-A {chain} ");
        let expected_drop = format!("-A {chain} -j DROP");
        let mut chain_rules = rules.lines().filter(|line| line.starts_with(&chain_prefix));
        if chain_rules.next_back() != Some(expected_drop.as_str()) {
            return Err(unsupported("default-drop egress rules were not verified"));
        }
    }
    Ok(())
}

async fn install_pinned_destinations(
    host: &dyn Host,
    firewall: &str,
    names: &NetworkNames,
    plan: &PinnedEgressPlan,
    ipv6: bool,
) -> Result<()> {
    for target in plan.targets() {
        let address = target.address();
        if is_ipv6(&address) != ipv6 {
            continue;
        }
        for protocol in ALLOWLIST_PROTOCOLS {
            firewall_success(
                host,
                firewall,
                [
                    "-A",
                    &names.forward_chain,
                    "-d",
                    &address.to_string(),
                    "-p",
                    protocol,
                    "--dport",
                    &target.port().to_string(),
                    "-j",
                    "ACCEPT",
                ],
            )
            .await?;
        }
    }
    Ok(())
}

async fn append_chain_owner_marker(
    host: &dyn Host,
    firewall: &str,
    chain: &str,
    owner_token: &str,
    ipv6: bool,
) -> Result<()> {
    let impossible_source = if ipv6 { "::/128" } else { "0.0.0.0/32" };
    firewall_success(
        host,
        firewall,
        [
            "-A",
            chain,
            "-s",
            impossible_source,
            "-m",
            "comment",
            "--comment",
            owner_token,
            "-j",
            "DROP",
        ],
    )
    .await
}

fn chain_has_owner_marker(rules: &str, chain: &str, owner_token: &str) -> bool {
    let chain_prefix = format!("-A {chain} ");
    rules.lines().any(|line| {
        line.starts_with(&chain_prefix)
            && line
                .split_whitespace()
                .collect::<Vec<_>>()
                .windows(2)
                .any(|pair| pair == ["--comment", owner_token])
            && line
                .split_whitespace()
                .collect::<Vec<_>>()
                .windows(2)
                .any(|pair| pair == ["-j", "DROP"])
    })
}

fn chain_has_rules(rules: &str, chain: &str) -> bool {
    let prefix = format!("-A {chain} ");
    rules.lines().any(|line| line.starts_with(&prefix))
}

fn chain_is_referenced(rules: &str, chain: &str) -> bool {
    rules.lines().any(|line| {
        let mut fields = line.split_whitespace();
        let (Some("-A"), Some(parent)) = (fields.next(), fields.next()) else {
            return false;
        };
        parent != chain
            && fields
                .collect::<Vec<_>>()
                .windows(2)
                .any(|pair| pair == ["-j", chain])
    })
}

fn deny_rules(ipv6: bool) -> Vec<Vec<String>> {
    if ipv6 {
        ["::1/128", "fd00:ec2::254/128"]
            .into_iter()
            .map(|prefix| vec!["-d".into(), prefix.into(), "-j".into(), "DROP".into()])
            .collect()
    } else {
        [
            "127.0.0.0/8",
            "169.254.169.254/32",
            "169.254.170.2/32",
            "100.100.100.200/32",
        ]
        .into_iter()
        .map(|prefix| vec!["-d".into(), prefix.into(), "-j".into(), "DROP".into()])
        .collect()
    }
}

fn is_ipv6(address: &IpAddr) -> bool {
    matches!(address, IpAddr::V6(_))
}

async fn verify_hook(
    host: &dyn Host,
    firewall: &str,
    parent: &str,
    bridge: &str,
    chain: &str,
) -> Result<()> {
    firewall_success(host, firewall, ["-C", parent, "-i", bridge, "-j", chain]).await
}

#[allow(clippy::too_many_lines)] // Keep ownership preflight and cleanup order together.
async fn cleanup_native(host: &dyn Host, namespace: &str, id: &BoxId) -> Result<()> {
    cleanup_native_with_attempt(host, namespace, id, &BTreeSet::new(), true).await
}

/// Reconcile a network create whose command result is ambiguous.
///
/// The network is removed by its inspected Docker ID only when owner, scope,
/// and attempt labels match this create attempt. A missing or foreign network is safe to leave alone;
/// an inconclusive inspection or removal error is returned so the sandbox
/// retains a cleanup record for a later retry.
async fn reconcile_ambiguous_network_create(
    host: &dyn Host,
    names: &NetworkNames,
    id: &BoxId,
) -> Result<()> {
    let inspect = docker_request(
        host,
        force_local_rootful_docker(vec![
            "docker".into(),
            "network".into(),
            "inspect".into(),
            "--format".into(),
            format!(
                "{{{{.Id}}}}|{{{{index .Labels \"{OWNER_LABEL}\"}}}}|{{{{index .Labels \"{SCOPE_LABEL}\"}}}}|{{{{index .Labels \"{ATTEMPT_LABEL}\"}}}}"
            ),
            names.network.clone(),
        ]),
    )
    .await?;
    if !inspect.succeeded() {
        let stderr = inspect.stderr_lossy();
        if stderr.contains("No such network") || stderr.contains("not found") {
            return Ok(());
        }
        return Err(Error::Backend {
            sandbox: "docker".to_owned(),
            operation: "inspect egress network ownership",
            message: stderr.trim().to_owned(),
        });
    }

    let inspect_stdout = inspect.stdout_lossy();
    let (network_id, owner, scope, attempt) = parse_network_ownership(&inspect_stdout)?;
    if owner != id.to_string() || scope != names.owner_token || attempt != names.attempt_token {
        return Ok(());
    }

    let remove = docker_request(
        host,
        force_local_rootful_docker(vec![
            "docker".into(),
            "network".into(),
            "rm".into(),
            network_id.clone(),
        ]),
    )
    .await?;
    if remove.succeeded() {
        return Ok(());
    }

    // Docker may report failure after deleting the network. Re-inspect the
    // deterministic name to distinguish that case from an uncertain cleanup.
    let verify = docker_request(
        host,
        force_local_rootful_docker(vec![
            "docker".into(),
            "network".into(),
            "inspect".into(),
            "--format".into(),
            format!(
                "{{{{.Id}}}}|{{{{index .Labels \"{OWNER_LABEL}\"}}}}|{{{{index .Labels \"{SCOPE_LABEL}\"}}}}|{{{{index .Labels \"{ATTEMPT_LABEL}\"}}}}"
            ),
            names.network.clone(),
        ]),
    )
    .await?;
    if !verify.succeeded() {
        let stderr = verify.stderr_lossy();
        if stderr.contains("No such network") || stderr.contains("not found") {
            return Ok(());
        }
        return Err(Error::Backend {
            sandbox: "docker".to_owned(),
            operation: "inspect egress network ownership",
            message: stderr.trim().to_owned(),
        });
    }
    let verify_stdout = verify.stdout_lossy();
    let (_network_id, owner, scope, attempt) = parse_network_ownership(&verify_stdout)?;
    if owner != id.to_string() || scope != names.owner_token || attempt != names.attempt_token {
        return Ok(());
    }
    Err(unsupported("owned egress network rollback failed"))
}

async fn reconcile_failed_network_create(
    host: &dyn Host,
    names: &NetworkNames,
    id: &BoxId,
    original_error: Error,
) -> Error {
    match reconcile_ambiguous_network_create(host, names, id).await {
        Ok(()) => original_error,
        Err(cleanup_error) => Error::EgressRollbackFailed {
            sandbox: "docker".to_owned(),
            message: format!("{original_error}; cleanup failed: {cleanup_error}"),
        },
    }
}

fn parse_network_ownership(output: &str) -> Result<(String, String, String, String)> {
    let fields = output.trim().split('|').collect::<Vec<_>>();
    if fields.len() != 4 || fields.iter().any(|field| field.is_empty()) {
        return Err(Error::Backend {
            sandbox: "docker".to_owned(),
            operation: "inspect egress network ownership",
            message: "Docker returned missing or malformed network identity or owner labels"
                .to_owned(),
        });
    }
    Ok((
        fields[0].to_owned(),
        fields[1].to_owned(),
        fields[2].to_owned(),
        fields[3].to_owned(),
    ))
}

fn parse_network_labels(output: &str) -> Result<(String, String, String)> {
    let fields = output.trim().split('|').collect::<Vec<_>>();
    if fields.len() != 3 || fields.iter().any(|field| field.is_empty()) {
        return Err(Error::Backend {
            sandbox: "docker".to_owned(),
            operation: "inspect egress network ownership",
            message: "Docker returned missing or malformed egress ownership labels".to_owned(),
        });
    }
    Ok((
        fields[0].to_owned(),
        fields[1].to_owned(),
        fields[2].to_owned(),
    ))
}

#[allow(clippy::too_many_lines)] // Keep ownership preflight and cleanup order together.
async fn cleanup_native_with_attempt(
    host: &dyn Host,
    namespace: &str,
    id: &BoxId,
    attempt_owned_chains: &BTreeSet<(String, String)>,
    allow_empty_orphan_reclaim: bool,
) -> Result<()> {
    let base_names = NetworkNames::for_box(namespace, id);
    let inspect = docker_request(
        host,
        force_local_rootful_docker(vec![
            "docker".into(),
            "network".into(),
            "inspect".into(),
            "--format".into(),
            format!(
                "{{{{index .Labels \"{OWNER_LABEL}\"}}}}|{{{{index .Labels \"{SCOPE_LABEL}\"}}}}|{{{{index .Labels \"{ATTEMPT_LABEL}\"}}}}"
            ),
            base_names.network.clone(),
        ]),
    )
    .await?;
    let names = if inspect.succeeded() {
        let fields = inspect.stdout_lossy();
        let (owner, scope, attempt) = parse_network_labels(&fields)?;
        if owner != id.to_string() || scope != base_names.owner_token {
            return Err(unsupported(
                "egress network ownership could not be verified",
            ));
        }
        if !valid_attempt_token(&attempt) {
            return Err(unsupported("egress network attempt identity is malformed"));
        }
        NetworkNames::for_attempt(namespace, id, &attempt)
    } else if inspect.stderr_lossy().contains("No such network")
        || inspect.stderr_lossy().contains("not found")
    {
        for firewall in ["iptables", "ip6tables"] {
            let rules = firewall_output(host, firewall, ["-S"]).await?;
            if rules.lines().any(|line| {
                line.split_whitespace()
                    .any(|word| word.starts_with(&base_names.chain_prefix))
            }) {
                return Err(unsupported(
                    "orphaned egress firewall chain has no verifiable Docker network owner",
                ));
            }
        }
        return Ok(());
    } else {
        return Err(unsupported("egress network cleanup could not be verified"));
    };

    let chains = [
        ("iptables", "DOCKER-USER", names.forward_chain.as_str()),
        ("iptables", "INPUT", names.input_chain.as_str()),
        ("ip6tables", "DOCKER-USER", names.forward_chain.as_str()),
        ("ip6tables", "INPUT", names.input_chain.as_str()),
    ];
    let mut owned_chains = BTreeSet::new();
    for (firewall, _, chain) in chains {
        let rules = firewall_output(host, firewall, ["-S"]).await?;
        let chain_prefix = format!("-A {chain} ");
        let chain_exists = rules
            .lines()
            .any(|line| line == format!("-N {chain}") || line.starts_with(&chain_prefix));
        if chain_exists {
            let created_by_attempt =
                attempt_owned_chains.contains(&(firewall.to_owned(), chain.to_owned()));
            let marked = chain_has_owner_marker(&rules, chain, &names.chain_owner_token);
            let recoverable_empty_orphan = (created_by_attempt || allow_empty_orphan_reclaim)
                && !chain_has_rules(&rules, chain)
                && !chain_is_referenced(&rules, chain);
            if !marked && !recoverable_empty_orphan {
                return Err(unsupported(
                    "egress firewall chain ownership could not be verified",
                ));
            }
            owned_chains.insert((firewall, chain));
        }
    }

    for (firewall, parent, chain) in chains {
        if !owned_chains.contains(&(firewall, chain)) {
            continue;
        }
        let hook = host
            .run(&ExecRequest::new([
                "sudo",
                "-n",
                firewall,
                "-w",
                "5",
                "-C",
                parent,
                "-i",
                &names.bridge,
                "-j",
                chain,
            ]))
            .await?;
        if hook.succeeded() {
            firewall_success(
                host,
                firewall,
                ["-D", parent, "-i", &names.bridge, "-j", chain],
            )
            .await?;
        }
        firewall_success(host, firewall, ["-F", chain]).await?;
        if let Err(delete_error) = firewall_success(host, firewall, ["-X", chain]).await {
            let ipv6 = firewall == "ip6tables";
            return match append_chain_owner_marker(
                host,
                firewall,
                chain,
                &names.chain_owner_token,
                ipv6,
            )
            .await
            {
                Ok(()) => Err(delete_error),
                Err(restore_error) => Err(Error::Backend {
                    sandbox: "docker".to_owned(),
                    operation: "restore egress firewall ownership marker",
                    message: format!(
                        "{delete_error}; restoring ownership marker failed: {restore_error}"
                    ),
                }),
            };
        }
        let remaining = firewall_output(host, firewall, ["-S"]).await?;
        if remaining
            .lines()
            .any(|line| line == format!("-N {chain}") || line.starts_with(&format!("-A {chain} ")))
        {
            return Err(unsupported(
                "egress firewall chain cleanup was not verified",
            ));
        }
    }

    docker_success(
        host,
        vec![
            "docker".into(),
            "network".into(),
            "rm".into(),
            names.network,
        ],
    )
    .await?;
    Ok(())
}

async fn firewall_output<const N: usize>(
    host: &dyn Host,
    firewall: &str,
    arguments: [&str; N],
) -> Result<String> {
    let mut argv = vec!["sudo", "-n", firewall, "-w", "5"];
    argv.extend(arguments);
    let output = host.run(&ExecRequest::new(argv)).await?;
    if !output.succeeded() {
        return Err(unsupported("required firewall command failed"));
    }
    Ok(output.stdout_lossy().into_owned())
}

async fn firewall_success<I, S>(host: &dyn Host, firewall: &str, arguments: I) -> Result<()>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut argv = vec![
        "sudo".to_owned(),
        "-n".to_owned(),
        firewall.to_owned(),
        "-w".to_owned(),
        "5".to_owned(),
    ];
    argv.extend(
        arguments
            .into_iter()
            .map(|argument| argument.as_ref().to_owned()),
    );
    let output = host.run(&ExecRequest::new(argv)).await?;
    if !output.succeeded() {
        return Err(unsupported("required firewall command failed"));
    }
    Ok(())
}

async fn docker_output(host: &dyn Host, argv: Vec<String>) -> Result<String> {
    let output = docker_request(host, force_local_rootful_docker(argv)).await?;
    if !output.succeeded() {
        return Err(unsupported(
            "Docker daemon identity or configuration could not be verified",
        ));
    }
    Ok(output.stdout_lossy().trim().to_owned())
}

async fn docker_success(host: &dyn Host, argv: Vec<String>) -> Result<String> {
    let output = docker_request(host, force_local_rootful_docker(argv)).await?;
    if !output.succeeded() {
        return Err(Error::Backend {
            sandbox: "docker".to_owned(),
            operation: "configure egress filtering",
            message: output.stderr_lossy().trim().to_owned(),
        });
    }
    Ok(output.stdout_lossy().trim().to_owned())
}

async fn docker_request(host: &dyn Host, argv: Vec<String>) -> Result<ExecOutput> {
    host.run(&ExecRequest::new(argv)).await
}

fn force_local_rootful_docker(argv: Vec<String>) -> Vec<String> {
    if argv.first().is_some_and(|program| program == "env") || has_local_docker_host_option(&argv) {
        return argv;
    }
    let mut forced = vec!["docker".into(), "--host".into(), DOCKER_SOCKET.into()];
    forced.extend(argv.into_iter().skip(1));
    forced
}

fn has_local_docker_host_option(argv: &[String]) -> bool {
    if argv.first().is_none_or(|program| program != "docker") {
        return false;
    }

    let mut index = 1;
    while let Some(argument) = argv.get(index) {
        if !argument.starts_with('-') {
            return false;
        }
        if argument == "--host" || argument == "-H" {
            return argv
                .get(index + 1)
                .is_some_and(|value| value == DOCKER_SOCKET);
        }
        if argument == "--config"
            || argument == "-c"
            || argument == "--context"
            || argument == "--log-level"
            || argument == "-l"
            || argument == "--tlscacert"
            || argument == "--tlscert"
            || argument == "--tlskey"
        {
            index += 2;
        } else {
            index += 1;
        }
    }
    false
}
