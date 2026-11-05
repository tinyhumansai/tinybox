//! The parts a [`BoxSpec`](crate::spec::BoxSpec) is assembled from.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::identity::{HostRef, SandboxRef, SnapshotId};

/// One machine-and-confinement pairing.
///
/// See the [module documentation](crate::spec) for why these two are separate
/// choices rather than a single backend enum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Placement {
    /// Which machine the process runs on.
    pub host: HostRef,
    /// What confines the process on that machine.
    pub sandbox: SandboxRef,
}

impl Placement {
    /// Pair a host with a sandbox.
    #[must_use]
    pub const fn new(host: HostRef, sandbox: SandboxRef) -> Self {
        Self { host, sandbox }
    }

    /// Whether `other` names the same machine, whatever confines it.
    ///
    /// Two placements sharing a host can exchange files directly instead of
    /// going through a sync, which is the main reason a caller asks.
    #[must_use]
    pub fn shares_host(&self, other: &Self) -> bool {
        self.host == other.host
    }
}

/// Where a workspace filesystem comes from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum WorkspaceSource {
    /// A directory on the host, mounted or synced into the box.
    LocalDir(PathBuf),
    /// An OCI image reference such as `alpine:3`.
    OciImage(String),
    /// A previously captured snapshot, which is also how templates are used.
    Snapshot(SnapshotId),
    /// A git repository cloned at a specific revision.
    GitRepo {
        /// The clone URL.
        url: String,
        /// The revision to check out — a branch, tag, or commit.
        rev: String,
    },
}

/// The limits applied to a workspace.
///
/// Every limit is positive; [`Resources::validate`] rejects zero because a zero
/// limit reads as "unlimited" to some backends and "deny everything" to others.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Resources {
    /// CPU allowance in thousandths of a core, so `1500` is one and a half.
    pub cpu_millis: u32,
    /// Maximum resident memory in bytes.
    pub memory_bytes: u64,
    /// Maximum number of processes and threads.
    pub pids_max: u32,
    /// Maximum writable filesystem size in bytes.
    pub disk_bytes: u64,
}

impl Resources {
    /// A modest default sized for an agent task rather than a build farm:
    /// two cores, 2 GiB of memory, 512 processes, and 8 GiB of disk.
    pub const DEFAULT: Self = Self {
        cpu_millis: 2_000,
        memory_bytes: 2 * 1024 * 1024 * 1024,
        pids_max: 512,
        disk_bytes: 8 * 1024 * 1024 * 1024,
    };

    /// Check that every limit is greater than zero.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ZeroResourceLimit`](crate::error::Error::ZeroResourceLimit) naming the first zero limit found,
    /// checked in declaration order.
    pub const fn validate(&self) -> Result<()> {
        if self.cpu_millis == 0 {
            return Err(Error::ZeroResourceLimit {
                limit: "cpu_millis",
            });
        }
        if self.memory_bytes == 0 {
            return Err(Error::ZeroResourceLimit {
                limit: "memory_bytes",
            });
        }
        if self.pids_max == 0 {
            return Err(Error::ZeroResourceLimit { limit: "pids_max" });
        }
        if self.disk_bytes == 0 {
            return Err(Error::ZeroResourceLimit {
                limit: "disk_bytes",
            });
        }
        Ok(())
    }
}

impl Default for Resources {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// How long a box lives, and whether it captures state as it runs.
///
/// Ephemeral and persistent boxes are policy over the same primitives, not
/// separate machinery: both create, exec, snapshot, and fork identically. Only
/// the reaper and the autosnapshot timer read this field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Lifecycle {
    /// Discarded once `ttl` elapses, with no snapshots taken on the way.
    ///
    /// This is the shape for untrusted agent code: disposable, served from a
    /// warm pool, and never resumed.
    Ephemeral {
        /// How long the box survives after creation.
        ttl: Duration,
    },
    /// Kept until explicitly destroyed, snapshotting on a cadence.
    ///
    /// This is the shape for a developer workspace: stopping captures state and
    /// archives it, and resuming forks the newest snapshot.
    Persistent {
        /// How often to snapshot while running, or `None` to snapshot only on
        /// stop.
        autosnapshot: Option<Duration>,
    },
}

impl Lifecycle {
    /// The default ephemeral lifetime: one hour.
    pub const DEFAULT_TTL: Duration = Duration::from_secs(60 * 60);

    /// The default autosnapshot cadence for persistent boxes: one minute.
    pub const DEFAULT_AUTOSNAPSHOT: Duration = Duration::from_secs(60);

    /// A persistent box snapshotting on the default cadence.
    #[must_use]
    pub const fn persistent() -> Self {
        Self::Persistent {
            autosnapshot: Some(Self::DEFAULT_AUTOSNAPSHOT),
        }
    }

    /// Whether this box should be snapshotted automatically, and how often.
    #[must_use]
    pub const fn autosnapshot_interval(&self) -> Option<Duration> {
        match self {
            Self::Ephemeral { .. } => None,
            Self::Persistent { autosnapshot } => *autosnapshot,
        }
    }

    /// Whether a reaper should destroy this box once its lifetime elapses.
    #[must_use]
    pub const fn is_ephemeral(&self) -> bool {
        matches!(self, Self::Ephemeral { .. })
    }
}

impl Default for Lifecycle {
    fn default() -> Self {
        Self::Ephemeral {
            ttl: Self::DEFAULT_TTL,
        }
    }
}

/// How long a box is kept for its owner, so one owner keeps one box across
/// uses.
///
/// Retention is not a lifetime: a retained box sleeps when idle and wakes on
/// the next command, and only [`Retention::delete_after_secs`] of sleeping ends
/// it. A backend that cannot honour it refuses the spec with
/// [`Error::Unsupported`] naming [`Capability::Retention`](crate::Capability::Retention); it never runs the
/// box as a disposable one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Retention {
    /// An opaque, stable identifier the host chooses for the box's owner.
    ///
    /// A later create with the same key finds the same box again, so a host
    /// must keep it unguessable-by-others and stable per owner. 1 to
    /// [`Retention::MAX_KEY_LEN`] characters of `[A-Za-z0-9_-]`.
    pub key: String,
    /// Seconds without a command before the box falls asleep. A backend clamps
    /// this to the range its service allows.
    pub idle_sleep_secs: u32,
    /// Seconds a box may sleep before it is deleted. Must be greater than zero.
    pub delete_after_secs: u64,
}

impl Retention {
    /// The longest accepted [`Retention::key`], in characters.
    pub const MAX_KEY_LEN: usize = 128;

    /// Check the key and the deletion delay.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidIdentifier`] when the key is empty, over-long, or has
    ///   a character outside `[A-Za-z0-9_-]`.
    /// - [`Error::InvalidRetention`] when `delete_after_secs` is zero, which
    ///   would read as "delete as soon as it sleeps".
    pub fn validate(&self) -> Result<()> {
        let key_ok = !self.key.is_empty()
            && self.key.len() <= Self::MAX_KEY_LEN
            && self
                .key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
        if !key_ok {
            return Err(Error::InvalidIdentifier {
                kind: "retention key",
                value: self.key.clone(),
            });
        }
        if self.delete_after_secs == 0 {
            return Err(Error::InvalidRetention {
                reason: "delete_after_secs must be greater than zero",
            });
        }
        Ok(())
    }
}

/// One published port: a guest port made reachable from the host.
///
/// Ports live on the spec rather than behind a handle because that is when they
/// can actually be applied — a container publishes ports at creation and cannot
/// gain one afterwards. Modelling them as a later operation would promise
/// something no backend can deliver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PortMapping {
    /// The port inside the box.
    pub guest: u16,
    /// The port on the host, or `None` to let the host choose a free one.
    pub host: Option<u16>,
}

impl PortMapping {
    /// Publish `guest` on an automatically chosen host port.
    #[must_use]
    pub const fn dynamic(guest: u16) -> Self {
        Self { guest, host: None }
    }

    /// Publish `guest` on exactly `host`.
    #[must_use]
    pub const fn fixed(guest: u16, host: u16) -> Self {
        Self {
            guest,
            host: Some(host),
        }
    }
}

/// What a workspace may reach over the network.
///
/// The default is [`NetworkPolicy::Denied`] because the common case is running
/// code that has no business making outbound connections, and an accidental
/// default of "open" is the kind of mistake that is only noticed afterwards.
///
/// [`NetworkPolicy::Open`] shares the host's network view and is the
/// highest-risk setting; see [`NetworkPolicy::is_highest_risk`].
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub enum NetworkPolicy {
    /// No network access at all.
    #[default]
    Denied,
    /// Outbound connections permitted; inbound not published.
    Egress,
    /// Outbound connections permitted only to the named hosts and ports.
    ///
    /// A backend that cannot enforce the list refuses the box with
    /// [`Error::ConstraintNotEnforced`]; it never widens the list to `Egress`.
    Allowlist(EgressAllowlist),
    /// Unrestricted, sharing the host's network view.
    Open,
}

/// The hosts and ports an [`NetworkPolicy::Allowlist`] box may reach.
///
/// # DNS handling
///
/// Hostnames are resolved **outside** the box, once, when the enforcing
/// backend builds its rules, and the resulting addresses are pinned: the box
/// is given those addresses (or a proxy that connects only to them) and no
/// resolver of its own. A name that later resolves elsewhere (a DNS rebinding
/// attempt) therefore reaches nothing new. A backend that cannot pin
/// resolution must report the network constraint `BestEffort` or
/// `Unsupported`, never `Enforced`.
///
/// The cloud metadata endpoints in [`EgressAllowlist::is_metadata_host`] are
/// refused at validation time, including legacy numeric IPv4 spellings such as
/// `0251.0376.0251.0376` and `0xa9fea9fe` for `169.254.169.254`. They must also
/// be blocked by the backend even when a hostname resolves to one of them.
///
/// Explicit loopback addresses and aliases are also invalid. This includes
/// IPv4/IPv6 loopback literals, IPv4-mapped loopback literals, scoped IPv6
/// literals such as `::1%1`, `localhost` names, and legacy numeric IPv4
/// spellings accepted by common resolvers (for example `127.1`, `2130706433`,
/// `0x7f000001`, and `0177.0.0.1`). These are checked as explicit allowlist
/// entries; enforcing backends must also reject resolved loopback addresses.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct EgressAllowlist {
    /// Host names or IP literals the box may connect to.
    pub hosts: Vec<String>,
    /// TCP ports the box may connect to on those hosts.
    pub ports: Vec<u16>,
}

impl EgressAllowlist {
    /// An allowlist of `hosts` on `ports`.
    #[must_use]
    pub fn new(
        hosts: impl IntoIterator<Item = impl Into<String>>,
        ports: impl IntoIterator<Item = u16>,
    ) -> Self {
        Self {
            hosts: hosts.into_iter().map(Into::into).collect(),
            ports: ports.into_iter().collect(),
        }
    }

    /// Whether `host` names a cloud instance-metadata endpoint, which no
    /// policy may ever allow. Matching ignores DNS case and terminal root dots,
    /// and recognizes legacy numeric IPv4 spellings of metadata addresses.
    #[must_use]
    pub fn is_metadata_host(host: &str) -> bool {
        let host = host
            .trim()
            .trim_end_matches('.')
            .trim_matches(['[', ']'])
            .to_ascii_lowercase();
        matches!(
            host.as_str(),
            "169.254.169.254"
                | "169.254.170.2"
                | "100.100.100.200"
                | "fd00:ec2::254"
                | "metadata.google.internal"
                | "metadata"
        ) || host.starts_with("::ffff:169.254.169.254")
            || Self::parse_legacy_ipv4(&host).is_some_and(|address| {
                address == Ipv4Addr::new(169, 254, 169, 254)
                    || address == Ipv4Addr::new(169, 254, 170, 2)
                    || address == Ipv4Addr::new(100, 100, 100, 200)
            })
    }

    /// Whether an allowlist entry explicitly names a loopback address or alias.
    fn is_loopback_host(host: &str) -> bool {
        let host = host
            .trim()
            .trim_matches(['[', ']'])
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if host == "localhost" || host.ends_with(".localhost") {
            return true;
        }

        match host.parse::<IpAddr>() {
            Ok(IpAddr::V4(address)) => address.is_loopback(),
            Ok(IpAddr::V6(address)) => Self::is_loopback_ipv6(address),
            Err(_) => {
                Self::parse_scoped_ipv6(&host).is_some_and(Self::is_loopback_ipv6)
                    || Self::parse_legacy_ipv4(&host).is_some_and(|address| address.is_loopback())
            }
        }
    }

    fn is_loopback_ipv6(address: Ipv6Addr) -> bool {
        address.is_loopback()
            || address
                .to_ipv4_mapped()
                .is_some_and(|mapped| mapped.is_loopback())
    }

    /// Parse an IPv6 address with a non-empty zone identifier, if present.
    fn parse_scoped_ipv6(host: &str) -> Option<Ipv6Addr> {
        let (address, scope_id) = host.split_once('%')?;
        if scope_id.is_empty() || scope_id.contains('%') {
            return None;
        }
        address.parse().ok()
    }

    /// Parse the legacy numeric IPv4 formats accepted by common resolvers.
    ///
    /// These formats are still relevant to validation because a backend may
    /// resolve the input through a system resolver that treats them as IP
    /// addresses rather than DNS names.
    fn parse_legacy_ipv4(host: &str) -> Option<Ipv4Addr> {
        let components: Vec<_> = host.split('.').collect();
        if !(1..=4).contains(&components.len()) || components.iter().any(|part| part.is_empty()) {
            return None;
        }

        let numbers: Vec<u32> = components
            .iter()
            .map(|part| {
                let number = if let Some(hex) =
                    part.strip_prefix("0x").or_else(|| part.strip_prefix("0X"))
                {
                    u64::from_str_radix(hex, 16).ok()
                } else if part.len() > 1 && part.starts_with('0') {
                    u64::from_str_radix(&part[1..], 8).ok()
                } else {
                    part.parse().ok()
                }?;
                u32::try_from(number).ok()
            })
            .collect::<Option<_>>()?;

        if numbers[..numbers.len() - 1]
            .iter()
            .any(|number| *number > u8::MAX.into())
        {
            return None;
        }
        let last = *numbers.last()?;
        let last_max = match numbers.len() {
            1 => u32::MAX,
            2 => 0x00ff_ffff,
            3 => 0x0000_ffff,
            4 => u8::MAX.into(),
            _ => return None,
        };
        if last > last_max {
            return None;
        }

        let address = match numbers.as_slice() {
            [whole] => *whole,
            [first, last] => (*first << 24) | *last,
            [first, second, last] => (*first << 24) | (*second << 16) | *last,
            [first, second, third, last] => {
                (*first << 24) | (*second << 16) | (*third << 8) | *last
            }
            _ => return None,
        };
        Some(Ipv4Addr::from(address))
    }

    /// Check the list is non-empty, well formed, and names no metadata or
    /// explicit loopback endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidNetworkPolicy`] naming the first problem.
    pub fn validate(&self) -> Result<()> {
        if self.hosts.is_empty() {
            return Err(Error::InvalidNetworkPolicy {
                reason: "allowlist has no hosts",
            });
        }
        if self.ports.is_empty() || self.ports.contains(&0) {
            return Err(Error::InvalidNetworkPolicy {
                reason: "allowlist needs at least one non-zero port",
            });
        }
        for host in &self.hosts {
            let trimmed = host.trim();
            if trimmed.is_empty()
                || trimmed.contains(char::is_whitespace)
                || trimmed.contains('/')
                || trimmed.contains('*')
            {
                return Err(Error::InvalidNetworkPolicy {
                    reason: "allowlist host is empty or not a plain host name",
                });
            }
            if Self::is_metadata_host(trimmed) {
                return Err(Error::InvalidNetworkPolicy {
                    reason: "allowlist names a cloud metadata endpoint",
                });
            }
            if Self::is_loopback_host(trimmed) {
                return Err(Error::InvalidNetworkPolicy {
                    reason: "allowlist names a loopback endpoint",
                });
            }
        }
        Ok(())
    }
}

impl NetworkPolicy {
    /// Whether the workspace can open outbound connections.
    #[must_use]
    pub const fn allows_egress(&self) -> bool {
        matches!(self, Self::Egress | Self::Allowlist(_) | Self::Open)
    }

    /// Whether this is the riskiest setting: the box shares the host's
    /// network view with no filtering at all.
    #[must_use]
    pub const fn is_highest_risk(&self) -> bool {
        matches!(self, Self::Open)
    }

    /// Check the policy is well formed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidNetworkPolicy`] for a malformed allowlist.
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Allowlist(list) => list.validate(),
            _ => Ok(()),
        }
    }

    /// Refuse an allowlist on a backend that cannot enforce one.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ConstraintNotEnforced`] for [`NetworkPolicy::Allowlist`].
    pub fn refuse_allowlist(&self, sandbox: &str) -> Result<()> {
        if matches!(self, Self::Allowlist(_)) {
            return Err(Error::ConstraintNotEnforced {
                sandbox: sandbox.to_owned(),
                constraint: crate::Constraint::Network,
                enforcement: crate::Enforcement::Unsupported,
            });
        }
        Ok(())
    }
}
