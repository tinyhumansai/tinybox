//! Tests for the `openshell` command construction.

use super::*;

use tinybox_core::{EgressAllowlist, HostRef, Placement, PortMapping, SandboxRef, SnapshotId};

fn spec() -> Result<BoxSpec> {
    Ok(BoxSpec::new(
        Placement::new(HostRef::new("local")?, SandboxRef::new(NAME)?),
        WorkspaceSource::OciImage("ghcr.io/example/agent:1".into()),
    ))
}

fn id() -> Result<BoxId> {
    BoxId::new("box-0")
}

#[test]
fn names_a_sandbox_after_its_namespace_and_box() -> Result<()> {
    assert_eq!(sandbox_name("chottu", &id()?), "tinybox-chottu-box-0");
    Ok(())
}

#[test]
fn accepts_only_dns_label_namespaces() {
    assert!(is_valid_namespace("chottu-prod"));
    assert!(is_valid_namespace("a1"));
    assert!(!is_valid_namespace(""));
    assert!(!is_valid_namespace("Chottu"));
    assert!(!is_valid_namespace("chottu_prod"));
    assert!(!is_valid_namespace("-chottu"));
    assert!(!is_valid_namespace("chottu-"));
    assert!(is_valid_namespace(&"a".repeat(49)));
    assert!(!is_valid_namespace(&"a".repeat(50)));
}

#[test]
fn accepts_a_uuid_namespace_and_still_fits_a_box_name() -> Result<()> {
    let namespace = "0f8fad5b-d9cb-469f-a165-70867728950e-1";
    assert!(is_valid_namespace(namespace));
    let argv = create(namespace, &BoxId::new("box-12")?, &spec()?)?;
    assert!(
        argv.iter()
            .any(|part| part == "tinybox-0f8fad5b-d9cb-469f-a165-70867728950e-1-box-12")
    );
    Ok(())
}

#[test]
fn refuses_a_box_that_pushes_a_long_namespace_past_the_name_limit() -> Result<()> {
    let refused = create(&"a".repeat(49), &BoxId::new("box-10")?, &spec()?);
    assert!(matches!(refused, Err(Error::InvalidIdentifier { .. })));
    Ok(())
}

#[test]
fn creates_from_the_image_with_limits_labels_and_no_prompts() -> Result<()> {
    let argv = create("chottu", &id()?, &spec()?)?;
    assert_eq!(
        argv,
        [
            "openshell",
            "sandbox",
            "create",
            "--name",
            "tinybox-chottu-box-0",
            "--from",
            "ghcr.io/example/agent:1",
            "--cpu",
            "2000m",
            "--memory",
            "2048Mi",
            "--label",
            "tinybox-box=box-0",
            "--label",
            "tinybox-namespace=chottu",
            "--no-auto-providers",
            "--no-tty",
            "--detach",
            "-o",
            "json",
        ]
    );
    Ok(())
}

#[test]
fn passes_whole_mebibyte_memory_exactly() -> Result<()> {
    let resources = Resources {
        cpu_millis: 250,
        memory_bytes: 100 * 1024 * 1024,
        ..Resources::DEFAULT
    };
    let argv = create("chottu", &id()?, &spec()?.with_resources(resources))?;
    assert!(argv.windows(2).any(|pair| pair == ["--cpu", "250m"]));
    assert!(argv.windows(2).any(|pair| pair == ["--memory", "100Mi"]));
    Ok(())
}

#[test]
fn refuses_memory_that_is_not_whole_mebibytes() -> Result<()> {
    let resources = Resources {
        memory_bytes: 100 * 1024 * 1024 + 1,
        ..Resources::DEFAULT
    };
    let refused = create("chottu", &id()?, &spec()?.with_resources(resources));
    assert!(matches!(
        refused,
        Err(Error::ConstraintNotEnforced {
            constraint: Constraint::Memory,
            ..
        })
    ));
    Ok(())
}

#[test]
fn passes_environment_by_name_only() -> Result<()> {
    let argv = create("chottu", &id()?, &spec()?.with_env("TOKEN", "secret-value"))?;
    assert!(argv.windows(2).any(|pair| pair == ["--env-from", "TOKEN"]));
    assert!(!argv.iter().any(|part| part.contains("secret-value")));
    Ok(())
}

#[test]
fn passes_no_policy_so_the_gateway_default_applies() -> Result<()> {
    let argv = create("chottu", &id()?, &spec()?)?;
    assert!(!argv.contains(&"--policy".to_owned()));
    Ok(())
}

#[test]
fn refuses_every_source_but_an_image() -> Result<()> {
    let sources = [
        WorkspaceSource::LocalDir("/work".into()),
        WorkspaceSource::Snapshot(SnapshotId::new("sha-0")?),
        WorkspaceSource::GitRepo {
            url: "https://example.test/repo".into(),
            rev: "main".into(),
        },
    ];
    for source in sources {
        let refused = create("chottu", &id()?, &spec()?.with_source(source));
        assert!(matches!(
            refused,
            Err(Error::UnsupportedWorkspaceSource { .. })
        ));
    }
    Ok(())
}

#[test]
fn refuses_any_network_but_denied() -> Result<()> {
    let policies = [
        NetworkPolicy::Egress,
        NetworkPolicy::Open,
        NetworkPolicy::Allowlist(EgressAllowlist::new(["pypi.org"], [443])),
    ];
    for policy in policies {
        let refused = create("chottu", &id()?, &spec()?.with_network(policy));
        assert!(matches!(
            refused,
            Err(Error::ConstraintNotEnforced {
                constraint: Constraint::Network,
                enforcement: Enforcement::Unsupported,
                ..
            })
        ));
    }
    Ok(())
}

#[test]
fn refuses_published_ports() -> Result<()> {
    let refused = create(
        "chottu",
        &id()?,
        &spec()?.with_port(PortMapping::dynamic(8080)),
    );
    assert!(matches!(
        refused,
        Err(Error::Unsupported {
            capability: Capability::PortForward,
            ..
        })
    ));
    Ok(())
}

#[test]
fn refuses_a_box_name_that_is_not_a_dns_label() -> Result<()> {
    let refused = create("chottu", &BoxId::new("Box_0")?, &spec()?);
    assert!(matches!(refused, Err(Error::InvalidIdentifier { .. })));
    let long = BoxId::new("b".repeat(60))?;
    let refused = create("chottu", &long, &spec()?);
    assert!(matches!(refused, Err(Error::InvalidIdentifier { .. })));
    Ok(())
}

#[test]
fn execs_without_a_terminal_or_login_shell() -> Result<()> {
    let request = ExecRequest::new(["python3", "-c", "print(1)"])
        .with_cwd("/sandbox")
        .with_env("MODE", "fast");
    let argv = exec("chottu", &id()?, &request)?;
    assert_eq!(
        argv,
        [
            "openshell",
            "sandbox",
            "exec",
            "--name",
            "tinybox-chottu-box-0",
            "--no-tty",
            "--no-login-shell",
            "--workdir",
            "/sandbox",
            "--env",
            "MODE=fast",
            "--",
            "python3",
            "-c",
            "print(1)",
        ]
    );
    Ok(())
}

#[test]
fn refuses_to_exec_an_empty_command() -> Result<()> {
    let refused = exec("chottu", &id()?, &ExecRequest::new(Vec::<String>::new()));
    assert!(matches!(refused, Err(Error::EmptyCommand { .. })));
    Ok(())
}

#[test]
fn gets_and_deletes_by_sandbox_name() -> Result<()> {
    assert_eq!(
        get("chottu", &id()?),
        [
            "openshell",
            "sandbox",
            "get",
            "tinybox-chottu-box-0",
            "-o",
            "json"
        ]
    );
    assert_eq!(
        delete("chottu", &id()?),
        ["openshell", "sandbox", "delete", "tinybox-chottu-box-0"]
    );
    Ok(())
}

#[test]
fn recognizes_a_missing_sandbox_in_any_case() {
    assert!(is_missing("Error: sandbox not found"));
    assert!(is_missing("status: NotFound, message: \"Not Found\""));
    assert!(!is_missing("connection refused"));
}

#[test]
fn maps_every_phase_to_a_box_state() -> Result<()> {
    let cases = [
        ("Provisioning", BoxState::Creating),
        ("Starting", BoxState::Creating),
        ("Ready", BoxState::Ready),
        ("Stopping", BoxState::Stopped),
        ("Stopped", BoxState::Stopped),
        ("Suspending", BoxState::Paused),
        ("Suspended", BoxState::Paused),
        ("Completed", BoxState::Archived),
        ("Deleting", BoxState::Archived),
        ("Error", BoxState::Failed),
        ("Unknown", BoxState::Failed),
        ("SomethingNew", BoxState::Failed),
    ];
    for (phase, state) in cases {
        let json = format!(r#"{{"name":"tinybox-chottu-box-0","phase":"{phase}"}}"#);
        assert_eq!(state_of(&json)?, state, "phase {phase}");
    }
    Ok(())
}

#[test]
fn reads_the_phase_nested_under_provisioning() -> Result<()> {
    let json = r#"{"name":"tinybox-chottu-box-0","provisioning":{"phase":"Ready"}}"#;
    assert_eq!(state_of(json)?, BoxState::Ready);
    Ok(())
}

#[test]
fn recognises_a_name_collision() {
    assert!(is_already_exists("Error: sandbox already exists"));
    assert!(!is_already_exists("timed out"));
}

#[test]
fn refuses_output_without_a_phase() {
    for output in ["not json", "{}", r#"{"phase": 3}"#] {
        assert!(matches!(state_of(output), Err(Error::Backend { .. })));
    }
}
