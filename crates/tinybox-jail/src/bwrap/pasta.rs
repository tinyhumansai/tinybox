//! A private network for an `allow_net` jail, from `pasta` (passt).
//!
//! Without this, a jail that allows network shares the host's network
//! namespace, so host loopback services and abstract unix sockets are
//! reachable from it. Here `pasta` creates a fresh user and network namespace
//! with user-mode networking out to the internet, and the jail is entered into
//! it.
//!
//! # Why a holder, not `pasta -- bwrap`
//!
//! `pasta` closes every inherited descriptor above 2 when it starts, and the
//! `bwrap` launch depends on inherited descriptors (the argument file, the
//! grant descriptors and the seccomp filters). So `pasta` runs only a holder
//! (`sh -c 'read _'`) that owns the namespaces; the launcher enters them with
//! `nsenter --user --net` by namespace descriptor, which keeps every other
//! descriptor, and then execs `bwrap`. Attaching `pasta` to namespaces `bwrap`
//! created is not an option on Ubuntu: its `AppArmor` user-namespace restriction
//! refuses the `setns`.
//!
//! # What the jail can reach
//!
//! `pasta` is only ever started with [`PASTA_ARGS`]: no port forwarding in
//! either direction (`-T none -U none`, so the jail cannot reach a service
//! bound to the host's loopback), no gateway mapping to the host
//! (`--no-map-gw`), and DNS only through [`DNS_ADDR`], which `pasta` forwards
//! to the host's resolver. The jail gets its own `/etc/resolv.conf` naming
//! that address. Abstract unix sockets belong to the network namespace, so the
//! host's are out of reach too.
//!
//! # Lifetime
//!
//! The holder reads a pipe whose only writer, once the jail has started, is
//! `bwrap` itself (`--sync-fd`). When `bwrap` exits, however it exits, the
//! holder sees end-of-file and exits, and `pasta` exits with it. Before the
//! hand-over the writer is held here, and [`Network`]'s `Drop` kills `pasta`.

use std::fs::File;
use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Where a trusted `pasta` may live.
const TRUSTED_PASTA: &[&str] = &["/usr/bin/pasta", "/usr/local/bin/pasta", "/bin/pasta"];

/// Where a trusted `nsenter` may live.
const TRUSTED_NSENTER: &[&str] = &["/usr/bin/nsenter", "/bin/nsenter", "/usr/local/bin/nsenter"];

/// The only way `pasta` is started: no port forwarding, no gateway mapping to
/// the host, DNS forwarded through [`DNS_ADDR`] only.
pub(super) const PASTA_ARGS: &[&str] = &[
    "--config-net",
    "--quiet",
    "--no-map-gw",
    "-T",
    "none",
    "-U",
    "none",
    "--dns-forward",
    DNS_ADDR,
];

/// The jail's resolver: `pasta` forwards DNS sent here to the host's.
pub(super) const DNS_ADDR: &str = "169.254.1.1";

/// How long the jail's network may take to come up.
const READY_TIMEOUT: Duration = Duration::from_secs(5);

/// A `pasta` and an `nsenter` found at trusted paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Pasta {
    program: PathBuf,
    nsenter: PathBuf,
}

/// The jail's `/etc/resolv.conf`.
pub(super) fn resolv_conf() -> String {
    format!("nameserver {DNS_ADDR}\n")
}

impl Pasta {
    /// `pasta` and `nsenter` at trusted paths, when both are there.
    pub(super) fn find(trusted: impl Fn(&Path) -> bool) -> Option<Self> {
        let first = |paths: &[&str]| paths.iter().map(PathBuf::from).find(|path| trusted(path));
        Some(Self {
            program: first(TRUSTED_PASTA)?,
            nsenter: first(TRUSTED_NSENTER)?,
        })
    }

    /// The `nsenter` the launcher enters the namespaces with.
    pub(super) fn nsenter(&self) -> &Path {
        &self.nsenter
    }

    /// Starts `pasta` with a holder and waits until its network is up.
    ///
    /// # Errors
    /// The spawn error; `InvalidData` when the holder cannot be identified as
    /// `pasta`'s child in a network namespace of its own; `TimedOut` when the
    /// network has no default route within [`READY_TIMEOUT`].
    pub(super) fn start(&self) -> io::Result<Network> {
        let (reader, writer) = io::pipe()?;
        let child = Command::new(&self.program)
            .args(PASTA_ARGS)
            .args(["--", "/bin/sh", "-c", "read _"])
            .env_clear()
            .stdin(Stdio::from(OwnedFd::from(reader)))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let mut network = Network {
            pasta: Some(child),
            user: None,
            net: None,
            writer: Some(writer.into()),
        };
        let pasta = network.pasta_pid()?;
        let deadline = Instant::now() + READY_TIMEOUT;
        let holder = wait_for(deadline, || holder_of(pasta))?;
        let (user, net) = open_namespaces(pasta, holder)?;
        network.user = Some(user);
        network.net = Some(net);
        wait_for(deadline, || has_default_route(holder).then_some(()))?;
        Ok(network)
    }
}

/// A running `pasta` and the namespaces of its holder.
#[derive(Debug)]
pub(super) struct Network {
    pasta: Option<Child>,
    user: Option<File>,
    net: Option<File>,
    /// The holder's only writer until it is handed to `bwrap`.
    writer: Option<OwnedFd>,
}

impl Network {
    fn pasta_pid(&self) -> io::Result<u32> {
        self.pasta
            .as_ref()
            .map(Child::id)
            .ok_or_else(|| io::Error::other("pasta already released"))
    }

    /// The descriptors the launcher needs: the holder's user and network
    /// namespaces, then the writer `bwrap` keeps with `--sync-fd`. Each is a
    /// duplicate; the originals stay here until [`Network::release`].
    ///
    /// # Errors
    /// The error from duplicating a descriptor.
    pub(super) fn descriptors(&self) -> io::Result<(OwnedFd, OwnedFd, OwnedFd)> {
        let missing = || io::Error::other("pasta network not started");
        let user = self.user.as_ref().ok_or_else(missing)?.try_clone()?;
        let net = self.net.as_ref().ok_or_else(missing)?.try_clone()?;
        let writer = self.writer.as_ref().ok_or_else(missing)?.try_clone()?;
        Ok((user.into(), net.into(), writer))
    }

    /// After the jail has started: drop this side's copies, so `bwrap` holds
    /// the holder's only writer, and reap `pasta` in the background when it
    /// exits.
    pub(super) fn release(mut self) {
        self.writer = None;
        self.user = None;
        self.net = None;
        if let Some(mut pasta) = self.pasta.take() {
            std::thread::spawn(move || {
                let _ = pasta.wait();
            });
        }
    }
}

#[cfg(test)]
impl Pasta {
    /// A `pasta` and `nsenter` at the given paths, without the trust check.
    pub(super) fn at(program: impl Into<PathBuf>, nsenter: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            nsenter: nsenter.into(),
        }
    }
}

#[cfg(test)]
impl Network {
    /// A network over the given descriptors with no `pasta` behind it, for
    /// tests of how a launch is wired.
    pub(super) fn fake(user: File, net: File, writer: OwnedFd) -> Self {
        Self {
            pasta: None,
            user: Some(user),
            net: Some(net),
            writer: Some(writer),
        }
    }
}

impl Drop for Network {
    fn drop(&mut self) {
        if let Some(mut pasta) = self.pasta.take() {
            let _ = pasta.kill();
            let _ = pasta.wait();
        }
    }
}

/// Polls `check` until it returns a value or `deadline` passes.
fn wait_for<T>(deadline: Instant, mut check: impl FnMut() -> Option<T>) -> io::Result<T> {
    loop {
        if let Some(value) = check() {
            return Ok(value);
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "pasta did not bring up the jail's network within {} s",
                    READY_TIMEOUT.as_secs()
                ),
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// The first child of `pasta`, read from `/proc`.
fn holder_of(pasta: u32) -> Option<u32> {
    let children = std::fs::read_to_string(format!("/proc/{pasta}/task/{pasta}/children")).ok()?;
    first_pid(&children)
}

/// The first pid in a `/proc/<pid>/task/<tid>/children` listing.
pub(super) fn first_pid(children: &str) -> Option<u32> {
    children.split_whitespace().next()?.parse().ok()
}

/// The parent pid from a `/proc/<pid>/status` file.
pub(super) fn parent_pid(status: &str) -> Option<u32> {
    status
        .lines()
        .find_map(|line| line.strip_prefix("PPid:"))
        .and_then(|value| value.trim().parse().ok())
}

/// Whether a `/proc/<pid>/net/route` table has a default route.
pub(super) fn default_route(table: &str) -> bool {
    table
        .lines()
        .skip(1)
        .any(|line| line.split_whitespace().nth(1) == Some("00000000"))
}

fn has_default_route(holder: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{holder}/net/route")).is_ok_and(|t| default_route(&t))
}

fn is_child_of(pasta: u32, holder: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{holder}/status"))
        .is_ok_and(|status| parent_pid(&status) == Some(pasta))
}

/// Opens the holder's user and network namespaces, checking before and after
/// that the pid still belongs to `pasta`'s child, and that the network
/// namespace is not this process's own.
fn open_namespaces(pasta: u32, holder: u32) -> io::Result<(File, File)> {
    let wrong = |what: &str| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("pasta holder {holder}: {what}"),
        )
    };
    if !is_child_of(pasta, holder) {
        return Err(wrong("not pasta's child"));
    }
    let user = File::open(format!("/proc/{holder}/ns/user"))?;
    let net = File::open(format!("/proc/{holder}/ns/net"))?;
    if !is_child_of(pasta, holder) {
        return Err(wrong("exited while its namespaces were opened"));
    }
    let own = std::fs::metadata("/proc/self/ns/net")?;
    let held = net.metadata()?;
    if (held.dev(), held.ino()) == (own.dev(), own.ino()) {
        return Err(wrong("shares this process's network namespace"));
    }
    Ok((user, net))
}

#[cfg(test)]
#[path = "pasta_tests.rs"]
mod tests;
