//! Tests for the v1 box row to v2 `box.boxes` body conversion.

use super::*;

fn v1() -> Value {
    json!({
        "id": "b",
        "state": "Paused",
        "spec": {
            "runner": {"host": "local", "sandbox": "passthrough"},
            "workspace": {"host": "local", "sandbox": "passthrough"},
            "source": {"GitRepo": {"url": "https://x.test/r", "rev": "main"}},
            "resources": {"cpu_millis": 1, "memory_bytes": 2, "pids_max": 3, "disk_bytes": 4},
            "lifecycle": {"Persistent": {"autosnapshot": {"secs": 5, "nanos": 7_000_000}}},
            "network": "Open",
            "env": {},
        },
        "created_at": {"secs_since_epoch": 2, "nanos_since_epoch": 3_000_000},
    })
}

#[test]
fn every_variant_takes_its_v2_tagged_form() {
    let body = to_body(v1()).expect("decodes");
    assert_eq!(body["state"], "paused");
    assert_eq!(body["created_ms"], 2003);
    assert_eq!(
        body["spec"]["source"],
        json!({"kind": "git_repo", "url": "https://x.test/r", "rev": "main"})
    );
    assert_eq!(
        body["spec"]["lifecycle"],
        json!({"kind": "persistent", "autosnapshot_ms": 5007})
    );
    assert_eq!(body["spec"]["network"], json!({"kind": "open"}));
    assert_eq!(body["spec"]["ports"], json!([]));
    assert_eq!(body["spec"]["hard_requirements"], json!([]));
    assert!(body.get("id").is_none(), "the id is the document id");
}

#[test]
fn hard_requirements_survive_the_v1_conversion() {
    let mut old = v1();
    old["spec"]["hard_requirements"] = json!(["cpu", "filesystem"]);
    let body = to_body(old).expect("decodes");
    assert_eq!(
        body["spec"]["hard_requirements"],
        json!(["cpu", "filesystem"])
    );
}

#[test]
fn a_persistent_box_without_autosnapshot_keeps_it_null() {
    let mut old = v1();
    old["spec"]["lifecycle"] = json!({"Persistent": {}});
    let body = to_body(old).expect("decodes");
    assert_eq!(body["spec"]["lifecycle"]["autosnapshot_ms"], Value::Null);
}

#[test]
fn an_unknown_state_is_refused() {
    let mut old = v1();
    old["state"] = json!("Levitating");
    to_body(old).expect_err("unknown state");
}

#[test]
fn the_other_sources_lifecycles_and_networks_convert() {
    let cases = [
        (
            "source",
            json!({"LocalDir": "/w"}),
            json!({"kind": "local_dir", "path": "/w"}),
        ),
        (
            "source",
            json!({"OciImage": "img:1"}),
            json!({"kind": "oci_image", "image": "img:1"}),
        ),
        (
            "source",
            json!({"Snapshot": "s1"}),
            json!({"kind": "snapshot", "snapshot": "s1"}),
        ),
        (
            "lifecycle",
            json!({"Ephemeral": {"ttl": {"secs": 3, "nanos": 0}}}),
            json!({"kind": "ephemeral", "ttl_ms": 3000}),
        ),
        ("network", json!("Denied"), json!({"kind": "denied"})),
        ("network", json!("Egress"), json!({"kind": "egress"})),
        (
            "network",
            json!({"Allowlist": {"hosts": ["a.test"], "ports": [443]}}),
            json!({"kind": "allowlist", "hosts": ["a.test"], "ports": [443]}),
        ),
    ];
    for (field, old, want) in cases {
        let mut row = v1();
        row["spec"][field] = old;
        let body = to_body(row).expect("decodes");
        assert_eq!(body["spec"][field], want);
    }
}

#[test]
fn every_state_has_its_snake_case_name() {
    for (old, want) in [
        ("Creating", "creating"),
        ("Ready", "ready"),
        ("Running", "running"),
        ("Paused", "paused"),
        ("Stopped", "stopped"),
        ("Archived", "archived"),
        ("Failed", "failed"),
    ] {
        let mut row = v1();
        row["state"] = json!(old);
        assert_eq!(to_body(row).expect("decodes")["state"], want);
    }
}

#[test]
fn a_box_without_a_creation_time_keeps_it_unknown() {
    let mut row = v1();
    row.as_object_mut().expect("row").remove("created_at");
    assert_eq!(to_body(row).expect("decodes")["created_ms"], Value::Null);
}
