//! Tests for the `BoxRecord` v2 body encoding and its match with the v1 migration.

use super::*;
use serde_json::json;
use std::time::{Duration, UNIX_EPOCH};
use tinybox_core::{
    BoxId, EgressAllowlist, HostRef, Lifecycle, NetworkPolicy, Placement, PortMapping, SandboxRef,
    SnapshotId, WorkspaceSource,
};

fn base_spec(source: WorkspaceSource) -> Result<BoxSpec> {
    Ok(BoxSpec::new(
        Placement::new(HostRef::new("local")?, SandboxRef::new("passthrough")?),
        source,
    ))
}

fn info_with(spec: BoxSpec) -> Result<BoxInfo> {
    Ok(BoxInfo::new(BoxId::new("b1")?, BoxState::Ready, spec))
}

fn round_trip(info: &BoxInfo) -> Result<BoxInfo> {
    let record = BoxRecord::try_from(info)?;
    let value = serde_json::to_value(&record).map_err(|e| Error::Store {
        operation: "encode",
        message: e.to_string(),
    })?;
    let back: BoxRecord = serde_json::from_value(value).map_err(|e| Error::Store {
        operation: "decode",
        message: e.to_string(),
    })?;
    Ok(back.into_info(info.id.clone()))
}

#[test]
fn the_body_is_snake_case_with_millisecond_times_and_no_id() -> Result<()> {
    let spec = base_spec(WorkspaceSource::LocalDir("/srv/work".into()))?
        .with_env("KEY", "value")
        .with_lifecycle(Lifecycle::Persistent {
            autosnapshot: Some(Duration::from_secs(60)),
        });
    let info = info_with(spec)?.created_at(UNIX_EPOCH + Duration::from_millis(1_700_000_000_123));
    let body = serde_json::to_value(BoxRecord::try_from(&info)?).expect("json");
    assert_eq!(
        body,
        json!({
            "state": "ready",
            "created_ms": 1_700_000_000_123_i64,
            "spec": {
                "runner": {"host": "local", "sandbox": "passthrough"},
                "workspace": {"host": "local", "sandbox": "passthrough"},
                "source": {"kind": "local_dir", "path": "/srv/work"},
                "resources": {
                    "cpu_millis": 2000,
                    "memory_bytes": 2_147_483_648_u64,
                    "pids_max": 512,
                    "disk_bytes": 8_589_934_592_u64,
                },
                "lifecycle": {"kind": "persistent", "autosnapshot_ms": 60_000},
                "network": {"kind": "denied"},
                "hard_requirements": [],
                "ports": [],
                "env": {"KEY": "value"},
            },
        })
    );
    Ok(())
}

#[test]
fn every_source_round_trips() -> Result<()> {
    for source in [
        WorkspaceSource::LocalDir("/w".into()),
        WorkspaceSource::OciImage("alpine:3".into()),
        WorkspaceSource::Snapshot(SnapshotId::new("snap-1")?),
        WorkspaceSource::GitRepo {
            url: "https://example.test/r.git".into(),
            rev: "main".into(),
        },
    ] {
        let info = info_with(base_spec(source)?)?;
        assert_eq!(round_trip(&info)?, info);
    }
    Ok(())
}

#[test]
fn every_network_policy_round_trips() -> Result<()> {
    for network in [
        NetworkPolicy::Denied,
        NetworkPolicy::Egress,
        NetworkPolicy::Allowlist(EgressAllowlist::new(["example.test"], [443])),
        NetworkPolicy::Open,
    ] {
        let info =
            info_with(base_spec(WorkspaceSource::OciImage("a".into()))?.with_network(network))?;
        assert_eq!(round_trip(&info)?, info);
    }
    Ok(())
}

#[test]
fn every_lifecycle_state_and_port_round_trips() -> Result<()> {
    for lifecycle in [
        Lifecycle::Ephemeral {
            ttl: Duration::from_secs(90),
        },
        Lifecycle::Persistent { autosnapshot: None },
        Lifecycle::persistent(),
    ] {
        for state in [
            BoxState::Creating,
            BoxState::Ready,
            BoxState::Running,
            BoxState::Paused,
            BoxState::Stopped,
            BoxState::Archived,
            BoxState::Failed,
        ] {
            let spec = base_spec(WorkspaceSource::OciImage("a".into()))?
                .with_lifecycle(lifecycle.clone())
                .with_port(PortMapping::fixed(80, 8080))
                .with_port(PortMapping::dynamic(22));
            let info = BoxInfo::new(BoxId::new("b1")?, state, spec);
            assert_eq!(round_trip(&info)?, info);
        }
    }
    Ok(())
}

#[test]
fn an_unknown_creation_time_stays_unknown() -> Result<()> {
    let info = info_with(base_spec(WorkspaceSource::OciImage("a".into()))?)?;
    let record = BoxRecord::try_from(&info)?;
    assert_eq!(record.created_ms, None);
    assert_eq!(round_trip(&info)?.created_at, None);
    Ok(())
}

#[test]
fn older_stored_records_default_hard_requirements_to_empty() -> Result<()> {
    let info = info_with(base_spec(WorkspaceSource::OciImage("a".into()))?)?;
    let mut value =
        serde_json::to_value(BoxRecord::try_from(&info)?).map_err(|e| Error::Store {
            operation: "encode",
            message: e.to_string(),
        })?;
    value["spec"]
        .as_object_mut()
        .ok_or_else(|| Error::Store {
            operation: "decode",
            message: "spec record must be an object".to_owned(),
        })?
        .remove("hard_requirements");

    let stored: BoxRecord = serde_json::from_value(value).map_err(|e| Error::Store {
        operation: "decode",
        message: e.to_string(),
    })?;
    assert_eq!(stored.into_info(info.id).spec.hard_requirements, []);
    Ok(())
}

#[test]
fn a_creation_time_keeps_millisecond_precision() -> Result<()> {
    let at = UNIX_EPOCH + Duration::from_millis(42_007);
    let info = info_with(base_spec(WorkspaceSource::OciImage("a".into()))?)?.created_at(at);
    assert_eq!(round_trip(&info)?.created_at, Some(at));
    Ok(())
}

#[test]
fn a_state_name_this_version_does_not_know_is_a_decode_error() {
    let body = json!({"state": "levitating", "spec": {}, "created_ms": null});
    assert!(serde_json::from_value::<BoxRecord>(body).is_err());
}

#[test]
fn the_contracts_v1_migration_matches_the_record_encoding() {
    let mut spec = base_spec(WorkspaceSource::LocalDir("/srv/w".into())).expect("spec");
    spec.lifecycle = Lifecycle::Ephemeral {
        ttl: Duration::from_secs(60),
    };
    spec.network = NetworkPolicy::Allowlist(EgressAllowlist::new(["a.test"], vec![443]));
    spec.hard_requirements = vec![tinybox_core::Constraint::Cpu];
    spec.ports.insert(PortMapping {
        guest: 80,
        host: None,
    });
    let info = info_with(spec)
        .expect("info")
        .created_at(UNIX_EPOCH + Duration::from_millis(1_700_000_000_005));
    let v1 = serde_json::to_value(&info).expect("v1 row");
    let migrated = tinybox_bus::storage::box_v1::to_body(v1).expect("migrates");
    let stored = serde_json::to_value(BoxRecord::try_from(&info).expect("record")).expect("json");
    assert_eq!(migrated, stored);
}
