//! Resolve and pin network allowlist destinations for the Docker firewall.
//!
//! The native Linux controller consumes pinned answers for firewall rules and
//! container `/etc/hosts` entries. Planning alone does not enforce traffic.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, SocketAddr},
};

use tinybox_core::{EgressAllowlist, Error, Result};

/// Resolves one hostname to all of its addresses in the environment where an
/// enforcing backend will use the result.
pub trait EgressResolver: std::fmt::Debug + Send + Sync {
    /// Resolve `hostname` once and return every address in the answer.
    ///
    /// # Errors
    ///
    /// Returns the resolver's error if the hostname cannot be resolved.
    fn resolve(&self, hostname: &str) -> std::io::Result<Vec<IpAddr>>;
}

/// Resolves allowlist names with the host's system resolver, once per name.
///
/// [`plan_egress_allowlist`] pins whatever this returns and refuses loopback,
/// metadata and IPv6 link-local answers, so the workload never depends on DNS
/// after the box is created.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemEgressResolver;

impl EgressResolver for SystemEgressResolver {
    fn resolve(&self, hostname: &str) -> std::io::Result<Vec<IpAddr>> {
        use std::net::ToSocketAddrs as _;

        // Port 0 is a placeholder: only the addresses are used.
        let mut addresses: Vec<IpAddr> = (hostname, 0)
            .to_socket_addrs()?
            .map(|socket| socket.ip())
            .collect();
        addresses.sort_unstable();
        addresses.dedup();
        Ok(addresses)
    }
}

/// A resolved allowlist plan whose destinations no longer depend on DNS.
///
/// The native Linux Docker controller uses each target both to install a
/// destination rule and to create a static hostname mapping for the workload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedEgressPlan {
    targets: Vec<PinnedEgressTarget>,
}

impl PinnedEgressPlan {
    /// The host, port, and pinned IP combinations that an enforcer must apply.
    #[must_use]
    pub fn targets(&self) -> &[PinnedEgressTarget] {
        &self.targets
    }
}

/// One permitted hostname and port paired with one pinned destination address.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PinnedEgressTarget {
    host: String,
    port: u16,
    address: IpAddr,
}

impl PinnedEgressTarget {
    /// The normalized allowlist hostname.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The permitted destination port.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// The address returned by the resolver, retained without another lookup.
    #[must_use]
    pub const fn address(&self) -> IpAddr {
        self.address
    }

    /// The pinned socket address an enforcing backend can connect to directly.
    #[must_use]
    pub const fn socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.address, self.port)
    }
}

/// Resolve and pin all destinations in an allowlist.
///
/// Every distinct hostname is passed to `resolver` exactly once. If any answer
/// is a cloud metadata or loopback address, the whole plan is rejected. Safe
/// private addresses are retained because this policy does not forbid them.
///
/// This function only prepares pinned data. It does not apply network rules;
/// the native Linux Docker controller consumes the result during preparation.
/// The resolver must answer in the environment where the eventual enforcer will
/// use the plan, which may be remote from the caller for an SSH-backed host.
///
/// # Errors
///
/// Returns [`Error::InvalidNetworkPolicy`] for a malformed allowlist, an empty
/// DNS answer, or any resolved metadata or loopback address. Returns
/// [`Error::ConstraintNotEnforced`] when an IPv6 link-local target needs an
/// interface scope that this backend cannot preserve. Resolver errors are
/// returned as [`Error::Backend`].
pub fn plan_egress_allowlist(
    allowlist: &EgressAllowlist,
    resolver: &dyn EgressResolver,
) -> Result<PinnedEgressPlan> {
    allowlist.validate()?;

    let mut addresses_by_host = BTreeMap::<String, BTreeSet<IpAddr>>::new();
    for configured_host in &allowlist.hosts {
        let host = normalize_host(configured_host);
        if addresses_by_host.contains_key(&host) {
            continue;
        }

        let addresses = match host.parse::<IpAddr>() {
            Ok(address) => vec![address],
            Err(_) => resolver.resolve(&host).map_err(|error| Error::Backend {
                sandbox: "docker".to_owned(),
                operation: "resolve an egress allowlist host",
                message: format!("{host}: {error}"),
            })?,
        };
        if addresses.is_empty() {
            return Err(Error::InvalidNetworkPolicy {
                reason: "allowlist host resolved to no addresses",
            });
        }
        let addresses = addresses
            .into_iter()
            .map(normalize_ip_address)
            .collect::<BTreeSet<_>>();
        if addresses.iter().any(is_forbidden_address) {
            return Err(Error::InvalidNetworkPolicy {
                reason: "allowlist host resolves to a metadata or loopback address",
            });
        }
        if addresses.iter().any(is_ipv6_link_local) {
            return Err(Error::ConstraintNotEnforced {
                sandbox: "docker".to_owned(),
                constraint: tinybox_core::Constraint::Network,
                enforcement: tinybox_core::Enforcement::Unsupported,
            });
        }
        addresses_by_host.insert(host, addresses);
    }

    let ports: BTreeSet<_> = allowlist.ports.iter().copied().collect();
    let mut targets = Vec::new();
    for (host, addresses) in addresses_by_host {
        for port in &ports {
            for address in &addresses {
                targets.push(PinnedEgressTarget {
                    host: host.clone(),
                    port: *port,
                    address: *address,
                });
            }
        }
    }

    Ok(PinnedEgressPlan { targets })
}

fn normalize_host(host: &str) -> String {
    host.trim().trim_matches(['[', ']']).to_ascii_lowercase()
}

fn normalize_ip_address(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map_or(IpAddr::V6(address), IpAddr::V4),
        IpAddr::V4(address) => IpAddr::V4(address),
    }
}

fn is_forbidden_address(address: &IpAddr) -> bool {
    if EgressAllowlist::is_metadata_host(&address.to_string()) {
        return true;
    }

    match address {
        IpAddr::V4(address) => address.is_loopback(),
        IpAddr::V6(address) => {
            address.is_loopback()
                || address.to_ipv4_mapped().is_some_and(|mapped| {
                    mapped.is_loopback() || EgressAllowlist::is_metadata_host(&mapped.to_string())
                })
        }
    }
}

fn is_ipv6_link_local(address: &IpAddr) -> bool {
    match address {
        IpAddr::V4(_) => false,
        IpAddr::V6(address) => address.segments()[0] & 0xffc0 == 0xfe80,
    }
}

#[cfg(test)]
#[path = "egress_tests.rs"]
mod tests;
