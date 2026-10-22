//! Tests for the jail index conversion between registry seconds and body milliseconds.

use super::*;
use serde_json::json;

fn registry_json() -> Value {
    json!({
        "schema_version": 1,
        "records": {
            "j1": {
                "id": "j1",
                "label": "build",
                "dir": "/srv/j1",
                "backend_at_create": "landlock",
                "created_at_unix": 1_700_000_000_u64,
                "updated_at_unix": 1_700_000_060_u64,
                "notes": null,
            },
        },
    })
}

fn body_json() -> Value {
    json!({
        "records": {
            "j1": {
                "id": "j1",
                "label": "build",
                "dir": "/srv/j1",
                "backend_at_create": "landlock",
                "created_ms": 1_700_000_000_000_i64,
                "updated_ms": 1_700_000_060_000_i64,
                "notes": null,
            },
        },
    })
}

#[test]
fn the_body_holds_millisecond_times_and_no_schema_version() {
    assert_eq!(to_body(registry_json()).expect("body"), body_json());
}

#[test]
fn the_registry_form_comes_back_from_the_body() {
    assert_eq!(from_body(body_json()), registry_json());
}

#[test]
fn an_index_without_records_converts_both_ways() {
    assert_eq!(
        to_body(json!({"records": {}})).expect("body"),
        json!({"records": {}})
    );
    assert_eq!(
        from_body(json!({"records": {}})),
        json!({"records": {}, "schema_version": 1})
    );
}

#[test]
fn a_time_that_overflows_milliseconds_is_invalid_data() {
    let mut index = registry_json();
    index["records"]["j1"]["created_at_unix"] = json!(u64::MAX);
    let error = to_body(index).expect_err("overflow");
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
}

#[test]
fn a_time_that_is_not_a_number_is_invalid_data() {
    let mut index = registry_json();
    index["records"]["j1"]["updated_at_unix"] = json!("yesterday");
    let error = to_body(index).expect_err("not a number");
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
}

#[test]
fn a_record_without_times_passes_through() {
    let index = json!({"records": {"j1": {"id": "j1"}}});
    assert_eq!(to_body(index.clone()).expect("body"), index);
}
