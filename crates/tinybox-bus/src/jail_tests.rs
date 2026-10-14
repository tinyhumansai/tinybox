//! Native jail vocabulary is serialized independently of implementation types.
use super::*;
use crate::{LocalGrants, UnixPathGrants};

#[test]
fn native_jail_request_keeps_explicit_enforcement_and_grants() -> Result<(), serde_json::Error> {
    let value = serde_json::json!({
        "read_only": ["/usr"], "read_write": [], "allow_net": true,
        "allow_subprocess": false, "enforcement": "enforced",
        "require_process_isolation": true,
    });
    let config: NativeJailConfig = serde_json::from_value(value.clone())?;
    assert_eq!(config.enforcement, JailEnforcement::Enforced);
    assert_eq!(serde_json::to_value(config)?, value);
    assert_eq!(serde_json::to_value(JailEnforcement::Declared)?, "declared");
    assert!(
        serde_json::from_value::<NativeJailConfig>(serde_json::json!({"read_only": []})).is_err()
    );
    Ok(())
}

#[test]
fn unix_path_fields_default_and_empty_values_keep_legacy_wire_shape()
-> Result<(), serde_json::Error> {
    let value = serde_json::json!({
        "read_only": ["/usr"], "read_write": [], "allow_net": true,
        "allow_subprocess": false, "enforcement": "enforced",
        "require_process_isolation": true
    });
    let config: NativeJailConfig = serde_json::from_value(value.clone())?;
    assert!(config.unix_paths.is_empty());
    assert_eq!(serde_json::to_value(config)?, value);
    let grants = UnixPathGrants::default();
    assert_eq!(serde_json::to_value(grants)?, serde_json::json!({}));
    Ok(())
}

#[test]
fn unix_grant_bytes_round_trip_without_text_conversion() -> Result<(), serde_json::Error> {
    let grants = UnixPathGrants {
        read_only: vec![vec![b'/', b't', 0xff]],
        read_write: vec![vec![b'/', b'w', 0xfe]],
    };
    let encoded = serde_json::to_value(&grants)?;
    assert_eq!(serde_json::from_value::<UnixPathGrants>(encoded)?, grants);
    Ok(())
}

#[test]
fn local_grant_result_defaults_to_the_legacy_utf8_wire_shape() -> Result<(), serde_json::Error> {
    let value = serde_json::json!({
        "read_only": ["/usr"],
        "read_write": ["/workspace"]
    });
    let grants: LocalGrants = serde_json::from_value(value.clone())?;
    assert!(grants.unix_paths.is_empty());
    assert_eq!(serde_json::to_value(grants)?, value);
    Ok(())
}
