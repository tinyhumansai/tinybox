//! Native jail vocabulary is serialized independently of implementation types.
use super::*;

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
fn deny_read_defaults_empty_and_round_trips() -> Result<(), serde_json::Error> {
    let mut value = serde_json::json!({
        "read_only": [], "read_write": [], "allow_net": true,
        "allow_subprocess": true, "enforcement": "declared",
        "require_process_isolation": false,
    });
    // A 1.19 request still decodes, and an empty list is not written back.
    let config: NativeJailConfig = serde_json::from_value(value.clone())?;
    assert_eq!(config.deny_read, Vec::<String>::new());
    assert_eq!(serde_json::to_value(&config)?, value);

    value["deny_read"] = serde_json::json!(["/Users/a/.ssh"]);
    let config: NativeJailConfig = serde_json::from_value(value.clone())?;
    assert_eq!(config.deny_read, ["/Users/a/.ssh"]);
    assert_eq!(serde_json::to_value(config)?, value);
    Ok(())
}

#[test]
fn native_resource_limits_are_optional_typed_and_round_trip() -> Result<(), serde_json::Error> {
    let old_request = serde_json::json!({
        "read_only": [], "read_write": [], "allow_net": true,
        "allow_subprocess": true, "enforcement": "declared",
        "require_process_isolation": false,
    });
    let old_config: NativeJailConfig = serde_json::from_value(old_request.clone())?;
    assert_eq!(old_config.resources, None);
    assert_eq!(serde_json::to_value(old_config)?, old_request);

    let mut request = old_request;
    request["resources"] = serde_json::json!({
        "cpu_millis": 500, "memory_bytes": 1_048_576,
        "pids_max": 32, "disk_bytes": 10_485_760,
    });
    let config: NativeJailConfig = serde_json::from_value(request.clone())?;
    assert_eq!(
        config.resources,
        Some(crate::ResourceLimits {
            cpu_millis: 500,
            memory_bytes: 1_048_576,
            pids_max: 32,
            disk_bytes: 10_485_760,
        })
    );
    assert_eq!(serde_json::to_value(config)?, request);
    Ok(())
}

#[test]
fn native_jail_21_resource_subset_is_additive_and_keeps_disk_explicit()
-> Result<(), serde_json::Error> {
    let jail = NativeJailConfig {
        read_only: vec![],
        read_write: vec![],
        allow_net: false,
        allow_subprocess: true,
        enforcement: JailEnforcement::Enforced,
        require_process_isolation: true,
        deny_read: vec![],
        resources: None,
    };
    let request = NativeJailRequest {
        jail: jail.clone(),
        resources: Some(NativeJailResourceRequest {
            cpu_millis: Some(1),
            memory_bytes: Some(64 * 1024 * 1024),
            pids_max: Some(16),
            disk_bytes: Some(1024),
        }),
    };
    let encoded = serde_json::to_value(&request)?;
    let decoded: NativeJailRequest = serde_json::from_value(encoded.clone())?;
    assert_eq!(decoded, request);
    assert_eq!(decoded.jail, jail);
    assert_eq!(
        decoded.resources.and_then(|limits| limits.disk_bytes),
        Some(1024)
    );
    assert_eq!(crate::NATIVE_JAIL_RESOURCES_VERSION, (2, 1));
    Ok(())
}
