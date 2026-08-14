//! Tests for the box specification and its parts.

use std::time::Duration;

use super::{BoxSpec, Lifecycle, NetworkPolicy, Placement, Resources, WorkspaceSource};
use crate::error::{Error, Result};
use crate::identity::{HostRef, SandboxRef, SnapshotId};

/// Build a placement, propagating identifier validation failures to the test.
fn placement(host: &str, sandbox: &str) -> Result<Placement> {
    Ok(Placement::new(
        HostRef::new(host)?,
        SandboxRef::new(sandbox)?,
    ))
}

/// A colocated local Docker box, the starting point for most cases here.
fn spec() -> Result<BoxSpec> {
    Ok(BoxSpec::new(
        placement("local", "docker")?,
        WorkspaceSource::OciImage("alpine:3".to_owned()),
    ))
}

#[test]
fn a_new_spec_colocates_the_runner_and_the_workspace() -> Result<()> {
    let spec = spec()?;

    assert!(spec.is_colocated());
    assert_eq!(spec.runner, spec.workspace);
    assert_eq!(spec.resources, Resources::DEFAULT);
    assert!(spec.env.is_empty());
    Ok(())
}

#[test]
fn a_runner_can_be_placed_apart_from_its_workspace() -> Result<()> {
    let spec = spec()?.with_runner(placement("local", "passthrough")?);

    assert!(!spec.is_colocated());
    assert_eq!(spec.runner.sandbox.as_str(), "passthrough");
    assert_eq!(spec.workspace.sandbox.as_str(), "docker");
    Ok(())
}

#[test]
fn a_local_runner_can_drive_a_remote_workspace() -> Result<()> {
    let spec = BoxSpec::new(
        placement("builder-01", "docker")?,
        WorkspaceSource::LocalDir("/srv/work".into()),
    )
    .with_runner(placement("local", "passthrough")?);

    assert!(!spec.is_colocated());
    assert!(!spec.runner.shares_host(&spec.workspace));
    Ok(())
}

#[test]
fn placements_on_one_machine_share_a_host() -> Result<()> {
    let docker = placement("builder-01", "docker")?;
    let bare = placement("builder-01", "passthrough")?;
    let elsewhere = placement("builder-02", "docker")?;

    assert!(docker.shares_host(&bare));
    assert!(!docker.shares_host(&elsewhere));
    Ok(())
}

#[test]
fn builders_replace_each_part_they_name() -> Result<()> {
    let limits = Resources {
        cpu_millis: 500,
        memory_bytes: 256 * 1024 * 1024,
        pids_max: 32,
        disk_bytes: 1024 * 1024 * 1024,
    };
    let spec = spec()?
        .with_resources(limits)
        .with_lifecycle(Lifecycle::persistent())
        .with_network(NetworkPolicy::Egress)
        .with_env("CI", "1")
        .with_env("CI", "true");

    assert_eq!(spec.resources, limits);
    assert_eq!(spec.network, NetworkPolicy::Egress);
    assert_eq!(spec.env.get("CI").map(String::as_str), Some("true"));
    assert_eq!(spec.env.len(), 1);
    Ok(())
}

#[test]
fn environment_order_does_not_change_spec_identity() -> Result<()> {
    let one = spec()?.with_env("A", "1").with_env("B", "2");
    let other = spec()?.with_env("B", "2").with_env("A", "1");

    assert_eq!(one, other);
    Ok(())
}

#[test]
fn validate_rejects_each_zero_limit_in_turn() -> Result<()> {
    for (limit, resources) in [
        (
            "cpu_millis",
            Resources {
                cpu_millis: 0,
                ..Resources::DEFAULT
            },
        ),
        (
            "memory_bytes",
            Resources {
                memory_bytes: 0,
                ..Resources::DEFAULT
            },
        ),
        (
            "pids_max",
            Resources {
                pids_max: 0,
                ..Resources::DEFAULT
            },
        ),
        (
            "disk_bytes",
            Resources {
                disk_bytes: 0,
                ..Resources::DEFAULT
            },
        ),
    ] {
        assert_eq!(
            spec()?.with_resources(resources).validate().err(),
            Some(Error::ZeroResourceLimit { limit })
        );
    }
    Ok(())
}

#[test]
fn validate_accepts_the_defaults() -> Result<()> {
    assert!(spec()?.validate().is_ok());
    assert_eq!(Resources::default(), Resources::DEFAULT);
    Ok(())
}

#[test]
fn a_box_is_ephemeral_for_an_hour_unless_told_otherwise() {
    let lifecycle = Lifecycle::default();

    assert!(lifecycle.is_ephemeral());
    assert_eq!(lifecycle.autosnapshot_interval(), None);
    assert_eq!(
        lifecycle,
        Lifecycle::Ephemeral {
            ttl: Duration::from_secs(3600),
        }
    );
}

#[test]
fn a_persistent_box_snapshots_on_a_cadence() {
    let lifecycle = Lifecycle::persistent();

    assert!(!lifecycle.is_ephemeral());
    assert_eq!(
        lifecycle.autosnapshot_interval(),
        Some(Duration::from_secs(60))
    );

    let on_stop_only = Lifecycle::Persistent { autosnapshot: None };
    assert!(!on_stop_only.is_ephemeral());
    assert_eq!(on_stop_only.autosnapshot_interval(), None);
}

#[test]
fn the_network_is_denied_by_default() {
    assert_eq!(NetworkPolicy::default(), NetworkPolicy::Denied);
    assert!(!NetworkPolicy::Denied.allows_egress());
    assert!(NetworkPolicy::Egress.allows_egress());
    assert!(NetworkPolicy::Open.allows_egress());
}

#[test]
fn every_workspace_source_is_expressible() -> Result<()> {
    let sources = [
        WorkspaceSource::LocalDir("/srv/work".into()),
        WorkspaceSource::OciImage("alpine:3".to_owned()),
        WorkspaceSource::Snapshot(SnapshotId::new("base-1")?),
        WorkspaceSource::GitRepo {
            url: "https://example.invalid/repo.git".to_owned(),
            rev: "main".to_owned(),
        },
    ];

    for source in &sources {
        let spec = BoxSpec::new(placement("local", "docker")?, source.clone());
        assert_eq!(&spec.source, source);
    }
    Ok(())
}
