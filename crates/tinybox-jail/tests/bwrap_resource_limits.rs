//! Linux-only: a bubblewrap jail's resource limits really hold.
//!
//! These need a working `bwrap` and a user manager delegated the `memory`
//! controller. They skip (with a note) when either is missing, unless
//! `TINYBOX_REQUIRE_BWRAP_LIMITS=1`, in which case a missing scope is a
//! failure. The shared-network refusal needs a host without `pasta`;
//! `TINYBOX_REQUIRE_SHARED_NETWORK=1` makes its presence a failure too.
#![cfg(target_os = "linux")]

use std::io;
use std::time::Instant;

use tinybox_core::{Constraint, Enforcement, Resources};
use tinybox_jail::{BubblewrapBackend, Jail, JailBackend};

#[allow(dead_code)]
mod support;

use support::*;

/// The backend, when it can hold a memory limit here.
fn limiting_backend() -> io::Result<Option<BubblewrapBackend>> {
    let Some(backend) = backend()? else {
        return Ok(None);
    };
    if backend.constraint_support().enforcement(Constraint::Memory) == Enforcement::Enforced {
        return Ok(Some(backend));
    }
    if std::env::var_os("TINYBOX_REQUIRE_BWRAP_LIMITS").is_some_and(|v| v == "1") {
        return Err(io::Error::other(
            "TINYBOX_REQUIRE_BWRAP_LIMITS=1 but the user manager holds no memory controller",
        ));
    }
    eprintln!("skipped: no user manager delegated the memory controller");
    Ok(None)
}

fn memory_jail(root: &std::path::Path, memory_bytes: u64) -> Jail {
    let mut jail = jail(root)
        .deny_net()
        .with_hard_requirements([Constraint::Memory]);
    jail.resources = Some(Resources {
        memory_bytes,
        ..Resources::DEFAULT
    });
    jail
}

/// Holds about 128 MiB in the shell's own memory, then reports.
const ALLOCATE: &str = "x=$(head -c 134217728 /dev/zero | tr '\\0' a); echo held ${#x}";

#[test]
fn a_hard_memory_limit_kills_a_jail_that_exceeds_it() -> io::Result<()> {
    let Some(backend) = limiting_backend()? else {
        return Ok(());
    };
    let start = Instant::now();
    let root = tempfile::tempdir()?;

    let (ok, out) = sh(&backend, &memory_jail(root.path(), 32 * 1024 * 1024), ALLOCATE)?;
    assert!(!ok, "128 MiB fit under a 32 MiB limit: {out}");
    assert!(!out.contains("held"), "{out}");

    // The same work under a roomy limit completes, so the limit is the cause.
    let (ok, out) = sh(&backend, &memory_jail(root.path(), 1024 * 1024 * 1024), ALLOCATE)?;
    assert!(ok && out.contains("held 134217728"), "{out}");
    done("memory-limit", start);
    Ok(())
}

#[test]
fn a_hard_limit_is_refused_for_a_jail_sharing_the_host_network() -> io::Result<()> {
    let Some(backend) = limiting_backend()? else {
        return Ok(());
    };
    if backend.networks_privately() {
        // With pasta the network is private, and the limit is allowed.
        if std::env::var_os("TINYBOX_REQUIRE_SHARED_NETWORK").is_some_and(|v| v == "1") {
            return Err(io::Error::other(
                "TINYBOX_REQUIRE_SHARED_NETWORK=1 but pasta gives allow_net jails a private network",
            ));
        }
        eprintln!("skipped: pasta gives allow_net jails a private network here");
        return Ok(());
    }
    let root = tempfile::tempdir()?;
    let mut shared = jail(root.path()).with_hard_requirements([Constraint::Memory]);
    shared.resources = Some(Resources::DEFAULT);
    assert_eq!(refused(&backend, &shared), Some(io::ErrorKind::Unsupported));
    Ok(())
}
