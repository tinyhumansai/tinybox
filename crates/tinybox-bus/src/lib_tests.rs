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
fn docker_run_vocabulary_is_typed_bounded_and_additive() -> Result<(), serde_json::Error> {
    let request = DockerRunRequest {
        workspace: "/tmp/workspace".into(),
        image: Some("debian:12".into()),
        command: "make test".into(),
        login_shell: true,
        network: Some("bridge".into()),
        memory_limit_mb: Some(2048),
        cpus: Some(2.5),
        read_only_rootfs: Some(false),
        read_only_mounts: vec!["/usr/lib".into(), "/etc/ssl/certs".into()],
        extra_cap_drops: vec!["NET_RAW".into()],
        env: BTreeMap::from([("MODE".into(), "test".into())]),
        label: Some("openhuman.sandbox=true".into()),
        timeout_ms: 120_000,
    };
    assert_eq!(METHODS[27], "RunDocker");
    assert_eq!(METHODS[28], "DockerStatus");
    assert_eq!(METHODS[29], "CleanupDocker");
    assert_eq!(METHODS[30], "RunDockerWithoutWorkspace");
    assert_eq!(METHODS[34], "StartNativeShellExec");
    assert_eq!(CONTRACT_VERSION, (1, 20));
    assert_eq!(MAX_DOCKER_RUN_TIMEOUT_MS, 86_400_000);
    let serialized = serde_json::to_value(&request)?;
    assert_eq!(serialized["read_only_rootfs"], false);
    assert_eq!(serialized["login_shell"], true);
    assert_eq!(
        serialized["read_only_mounts"],
        serde_json::json!(["/usr/lib", "/etc/ssl/certs"])
    );
    assert_eq!(
        serialized["extra_cap_drops"],
        serde_json::json!(["NET_RAW"])
    );
    assert_eq!(
        serde_json::from_value::<DockerRunRequest>(serialized)?,
        request
    );
    let timeout_default: DockerRunRequest = serde_json::from_value(serde_json::json!({
        "workspace": "/tmp/workspace", "command": "true"
    }))?;
    assert_eq!(timeout_default.timeout_ms, DEFAULT_DOCKER_RUN_TIMEOUT_MS);
    assert!(!timeout_default.login_shell);
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
    assert_eq!(CONTRACT_VERSION, (1, 20));
    assert!(is_compatible(CONTRACT_VERSION));
    assert!(!is_compatible((1, 19)));
    assert!(!is_compatible((1, 18)));
    assert!(!is_compatible((1, 8)));
    assert!(!is_compatible((1, 7)));
    assert!(!is_compatible((1, 6)));
    assert!(!is_compatible((1, 5)));
    assert!(!is_compatible((1, 4)));
    assert!(!is_compatible((1, 3)));
    assert!(!is_compatible((1, 2)));
    assert!(!is_compatible((1, 0)));
    assert!(!is_compatible((0, 99)));
    assert!(!is_compatible((2, 1)));
    let capabilities = ModuleCapabilities {
        contract_version: CONTRACT_VERSION,
        create_backends: vec!["passthrough".into()],
        exec_backends: Vec::new(),
        spawn_backends: Vec::new(),
    };
    let snapshot = serde_json::json!({"contract_version":[1,20],"create_backends":["passthrough"],"exec_backends":[],"spawn_backends":[]});
    assert_eq!(serde_json::to_value(&capabilities)?, snapshot);
    assert_eq!(
        serde_json::from_value::<ModuleCapabilities>(snapshot)?,
        capabilities
    );
    Ok(())
}

#[test]
fn no_workspace_docker_operation_is_present_in_the_contract() {
    assert_eq!(METHODS.get(30), Some(&"RunDockerWithoutWorkspace"));
    assert_eq!(
        METHODS
            .iter()
            .filter(|method| **method == "RunDockerWithoutWorkspace")
            .count(),
        1
    );
    assert_eq!(CONTRACT_VERSION, (1, 20));
}

#[test]
fn command_classes_keep_wire_labels_and_security_order() -> Result<(), serde_json::Error> {
    let classes = [
        CommandClass::Read,
        CommandClass::Write,
        CommandClass::Network,
        CommandClass::Install,
        CommandClass::Destructive,
    ];
    assert_eq!(
        serde_json::to_value(classes)?,
        serde_json::json!(["read", "write", "network", "install", "destructive"])
    );
    for pair in classes.windows(2) {
        assert!(pair[0] < pair[1]);
    }
    assert_eq!(
        serde_json::from_value::<Vec<CommandClass>>(serde_json::to_value(classes)?)?,
        classes
    );
    Ok(())
}

#[test]
fn command_analysis_wire_facts_round_trip_without_host_policy() -> Result<(), serde_json::Error> {
    let snapshot = serde_json::json!({
        "segments": [{"source": "echo hello", "command": "echo hello", "basename": "echo",
            "normalized_name": "echo", "arguments": ["hello"], "class": "read",
            "leading_env_assignment": false, "dangerous_env_prefix": false, "executor": false}],
        "hidden_execution": false, "redirection": false, "expansion": false,
        "tee": false, "background": false, "literal_words": ["echo", "hello"]
    });
    let facts: CommandAnalysis = serde_json::from_value(snapshot.clone())?;
    assert_eq!(serde_json::to_value(facts)?, snapshot);
    Ok(())
}

#[test]
fn workspace_file_transfers_are_chunked_typed_and_bounded() -> Result<(), serde_json::Error> {
    assert_eq!(MAX_FILE_CHUNK_BYTES, 64 * 1024);
    assert_eq!(MAX_FILE_TRANSFERS_PER_RESOURCE, 8);
    assert_eq!(MAX_FILE_BYTES, 256 * 1024 * 1024);
    assert!(METHODS.contains(&"BeginFileRead"));
    assert!(METHODS.contains(&"ReadFileChunk"));
    assert!(METHODS.contains(&"FinishFileRead"));
    assert!(METHODS.contains(&"BeginFileWrite"));
    assert!(METHODS.contains(&"WriteFileChunk"));
    assert!(METHODS.contains(&"FinishFileWrite"));
    assert!(METHODS.contains(&"AbortFileWrite"));

    let begin = BeginFileReadRequest {
        resource: ResourceId("resource-1".into()),
        transfer: ResourceId("transfer-1".into()),
        path: "nested/report.bin".into(),
    };
    assert_eq!(
        serde_json::to_value(&begin)?,
        serde_json::json!({"resource":"resource-1", "transfer":"transfer-1", "path":"nested/report.bin"})
    );
    assert_eq!(
        serde_json::from_value::<BeginFileReadRequest>(serde_json::to_value(begin.clone())?)?,
        begin
    );

    let chunk = WriteFileChunkRequest {
        resource: ResourceId("resource-1".into()),
        transfer: ResourceId("transfer-1".into()),
        offset: 0,
        bytes: vec![0, 1, 255],
    };
    let snapshot = serde_json::json!({
        "resource":"resource-1", "transfer":"transfer-1", "offset":0,
        "bytes":[0, 1, 255]
    });
    assert_eq!(serde_json::to_value(&chunk)?, snapshot);
    assert_eq!(
        serde_json::from_value::<WriteFileChunkRequest>(snapshot)?,
        chunk
    );
    Ok(())
}

#[test]
fn local_grant_configuration_defaults_and_floor_round_trip() -> Result<(), serde_json::Error> {
    let config: LocalGrantConfig = serde_json::from_str("{}")?;
    assert!(config.toolchain_homes);
    assert!(!config.allow_proc);
    let request = ResolveLocalGrantsRequest {
        home: Some("/operator".into()),
        config,
        protected: ProtectedPaths {
            components: vec![".ssh".into()],
            component_pairs: vec![[".cargo".into(), "credentials.toml".into()]],
            prefixes: vec!["/etc".into()],
            credential_roots: vec!["/operator/.ssh".into()],
        },
        allow_unix_paths: false,
    };
    assert_eq!(
        serde_json::from_value::<ResolveLocalGrantsRequest>(serde_json::to_value(&request)?)?,
        request
    );
    let wire = serde_json::to_value(&request)?;
    assert_eq!(wire.get("allow_unix_paths"), None);
    Ok(())
}

#[test]
fn shell_selection_wire_defaults_preserve_safe_pipeline_behavior() -> Result<(), serde_json::Error>
{
    let request: SelectShellRequest =
        serde_json::from_value(serde_json::json!({"command":"false | true"}))?;
    assert!(!request.preserve_pipeline_status);
    assert_eq!(request.runtime_path, None);
    assert!(!request.python_utf8);
    let invocation = ShellInvocation {
        flavor: ShellFlavor::Cmd,
        program: "cmd".into(),
        arguments: vec!["/C".into()],
        raw_arguments: Some(r#"echo "quoted payload""#.into()),
        bootstrap_environment: vec!["SystemRoot".into()],
        remove_environment: Vec::new(),
    };
    let value = serde_json::to_value(&invocation)?;
    assert_eq!(value["flavor"], "cmd");
    assert_eq!(value["raw_arguments"], r#"echo "quoted payload""#);
    assert_eq!(
        serde_json::from_value::<ShellInvocation>(value)?,
        invocation
    );
    assert_eq!(METHODS[31], "ResolveLocalGrants");
    assert_eq!(METHODS[32], "SelectShell");
    assert!(!is_compatible((1, 9)));
    Ok(())
}

#[test]
fn older_shell_invocations_default_the_startup_removal_vocabulary() -> Result<(), serde_json::Error>
{
    let invocation: ShellInvocation = serde_json::from_value(serde_json::json!({
        "flavor":"posix", "program":"sh", "arguments":["-c","true"],
        "raw_arguments":null, "bootstrap_environment":[]
    }))?;
    assert_eq!(invocation.remove_environment, Vec::<String>::new());
    Ok(())
}

#[test]
fn native_shell_wire_defaults_close_stdin_and_keep_a_bounded_runtime()
-> Result<(), serde_json::Error> {
    let request: ShellExecRequest = serde_json::from_value(serde_json::json!({
        "process":"process", "resource":"resource", "shell":{"command":"true"},
        "state_dir":"/state"
    }))?;
    assert_eq!(request.timeout_ms, 30_000);
    assert_eq!(request.stdin, None);
    assert_eq!(request.cwd, None);
    assert_eq!(request.jail, None);
    assert_eq!(request.extra_env, std::collections::BTreeMap::new());
    assert_eq!(METHODS[33], "StartShellExec");
    assert_eq!(METHODS[34], "StartNativeShellExec");
    assert!(!is_compatible((1, 13)));
    assert!(!is_compatible((1, 10)));
    Ok(())
}

#[test]
fn named_members_resolve_to_the_method_catalogue_in_order() {
    use names::*;
    let expected = [
        DESCRIBE,
        CREATE,
        EXEC,
        INSPECT,
        CLOSE,
        SPAWN,
        IS_RUNNING,
        CANCEL,
        ANALYZE_SHELL,
        RESERVE,
        CAPABILITIES,
        SHUTDOWN,
        FORWARD,
        CLOSE_FORWARD,
        JAIL_STATUS,
        ANALYZE_COMMAND,
        BEGIN_FILE_READ,
        READ_FILE_CHUNK,
        FINISH_FILE_READ,
        BEGIN_FILE_WRITE,
        WRITE_FILE_CHUNK,
        FINISH_FILE_WRITE,
        ABORT_FILE_WRITE,
        START_EXEC,
        READ_OUTPUT,
        RELEASE_OUTPUT,
        START_JAILED_EXEC,
        RUN_DOCKER,
        DOCKER_STATUS,
        CLEANUP_DOCKER,
        RUN_DOCKER_WITHOUT_WORKSPACE,
        RESOLVE_LOCAL_GRANTS,
        SELECT_SHELL,
        START_SHELL_EXEC,
        START_NATIVE_SHELL_EXEC,
        VALIDATE_DOCKER_POLICY,
    ];
    assert_eq!(METHODS, &expected[..]);
    assert_eq!(DESCRIBE, "Describe");
    assert_eq!(ANALYZE_SHELL, "AnalyzeShell");
    let mut unique = METHODS.to_vec();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(unique.len(), METHODS.len());
}

#[test]
fn docker_policy_validation_is_a_standalone_appended_member() -> Result<(), serde_json::Error> {
    assert_eq!(METHODS.last(), Some(&"ValidateDockerPolicy"));
    assert_eq!(METHODS[35], "ValidateDockerPolicy");
    assert_eq!(names::VALIDATE_DOCKER_POLICY, "ValidateDockerPolicy");
    let request: DockerPolicyRequest = serde_json::from_value(serde_json::json!({}))?;
    assert_eq!(request, DockerPolicyRequest::default());
    let request = DockerPolicyRequest {
        network: Some("host".into()),
        workspace: Some("/".into()),
        read_only_mounts: vec!["/etc".into()],
    };
    assert_eq!(
        serde_json::from_value::<DockerPolicyRequest>(serde_json::to_value(&request)?)?,
        request
    );
    let report = DockerPolicyReport {
        issues: vec!["x".into()],
    };
    assert_eq!(
        serde_json::from_value::<DockerPolicyReport>(serde_json::to_value(&report)?)?,
        report
    );
    Ok(())
}

#[test]
fn native_shell_request_hides_no_window_unless_asked() -> Result<(), serde_json::Error> {
    let request: ShellExecRequest = serde_json::from_value(serde_json::json!({
        "process":"p", "resource":"r", "shell":{"command":"true"}, "state_dir":"/s"
    }))?;
    assert!(!request.hide_window);
    let request: ShellExecRequest = serde_json::from_value(serde_json::json!({
        "process":"p", "resource":"r", "shell":{"command":"true"}, "state_dir":"/s",
        "hide_window": true
    }))?;
    assert!(request.hide_window);
    Ok(())
}
