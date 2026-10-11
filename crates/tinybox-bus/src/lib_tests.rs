//! Serialized contract compatibility tests.
use super::*;

#[test]
fn command_optional_fields_default_when_absent() -> Result<(), serde_json::Error> {
    let request: ExecRequest =
        serde_json::from_str(r#"{"resource":"box-1","argv":["echo","hello"]}"#)?;
    assert_eq!(request.resource, ResourceId("box-1".into()));
    assert!(request.cwd.is_none());
    assert!(request.env.is_empty());
    assert!(request.stdin.is_none());
    assert_eq!(
        serde_json::from_value::<ExecRequest>(serde_json::to_value(&request)?)?,
        request
    );
    Ok(())
}

#[test]
fn create_environment_defaults_and_workspace_round_trips() -> Result<(), serde_json::Error> {
    let request: CreateRequest = serde_json::from_str(
        r#"{"resource":"create-1","backend":"docker","workspace":{"Image":"alpine"}}"#,
    )?;
    assert!(request.env.is_empty());
    assert_eq!(
        serde_json::from_value::<CreateRequest>(serde_json::to_value(&request)?)?,
        request
    );
    Ok(())
}

#[test]
fn host_gateway_and_docker_facts_are_additive_and_default_safely() -> Result<(), serde_json::Error>
{
    let legacy: CreateRequest = serde_json::from_str(
        r#"{"resource":"create-1","backend":"docker","workspace":{"Image":"alpine"}}"#,
    )?;
    assert_eq!(legacy.host, HostConfig::Local);
    assert_eq!(legacy.network, NetworkPolicy::Denied);
    assert_eq!(legacy.resources, ResourceLimits::default());
    assert_eq!(legacy.ports, Vec::<PortMapping>::new());

    let ssh: HostConfig = serde_json::from_value(serde_json::json!({
        "Ssh": {
            "destination": "builder.example",
            "port": 2202,
            "identity": "/keys/build",
            "known_hosts": "/state/tinybox-known-hosts",
            "accept_new_host_key": false
        }
    }))?;
    let request = CreateRequest {
        resource: ResourceId("create-ssh".into()),
        backend: "docker".into(),
        host: ssh,
        workspace: Workspace::Image("alpine".into()),
        network: NetworkPolicy::Egress,
        resources: ResourceLimits::default(),
        ports: vec![PortMapping {
            guest: 8080,
            host: None,
        }],
        env: BTreeMap::new(),
    };
    assert_eq!(
        serde_json::from_value::<CreateRequest>(serde_json::to_value(&request)?)?,
        request
    );

    let forward = ForwardInfo {
        resource: ResourceId("create-ssh".into()),
        forward: ResourceId("forward-1".into()),
        local_address: "127.0.0.1:54321".into(),
    };
    assert_eq!(
        serde_json::from_value::<ForwardInfo>(serde_json::to_value(&forward)?)?,
        forward
    );
    Ok(())
}

#[test]
fn version_and_capability_wire_snapshot_preserve_contract_compatibility()
-> Result<(), serde_json::Error> {
    assert_eq!(CONTRACT_VERSION, (1, 2));
    assert!(is_compatible(CONTRACT_VERSION));
    assert!(is_compatible((1, 2)));
    assert!(!is_compatible((1, 0)));
    assert!(!is_compatible((0, 99)));
    assert!(!is_compatible((2, 1)));
    let capabilities = ModuleCapabilities {
        contract_version: CONTRACT_VERSION,
        create_backends: vec!["passthrough".into()],
        exec_backends: Vec::new(),
        spawn_backends: Vec::new(),
    };
    let snapshot = serde_json::json!({"contract_version":[1,2],"create_backends":["passthrough"],"exec_backends":[],"spawn_backends":[]});
    assert_eq!(serde_json::to_value(&capabilities)?, snapshot);
    assert_eq!(
        serde_json::from_value::<ModuleCapabilities>(snapshot)?,
        capabilities
    );
    Ok(())
}
