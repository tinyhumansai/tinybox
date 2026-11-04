//! The pure contract mappings: spec refusals, the exec shell composition and
//! output coding, the resource mapping, and the status→state table — all
//! without a network or a live service.

use super::*;

use tinybox_core::{HostRef, Placement, Resources, SandboxRef};

fn oci_spec() -> Result<BoxSpec> {
    Ok(BoxSpec::new(
        Placement::new(HostRef::new("local")?, SandboxRef::new(NAME)?),
        WorkspaceSource::OciImage("agent37-base".to_owned()),
    ))
}

#[test]
fn a_non_oci_source_is_refused() -> Result<()> {
    let spec = BoxSpec::new(
        Placement::new(HostRef::new("local")?, SandboxRef::new(NAME)?),
        WorkspaceSource::LocalDir("/tmp".into()),
    );
    assert!(matches!(
        check_spec(&spec),
        Err(Error::UnsupportedWorkspaceSource { .. })
    ));
    Ok(())
}

#[test]
fn a_non_denied_network_is_refused() -> Result<()> {
    let mut spec = oci_spec()?;
    spec.network = NetworkPolicy::Open;
    assert!(matches!(
        check_spec(&spec),
        Err(Error::ConstraintNotEnforced { .. })
    ));
    Ok(())
}

#[test]
fn an_oci_spec_passes_check_and_yields_its_template_name() -> Result<()> {
    assert_eq!(check_spec(&oci_spec()?)?, "agent37-base");
    Ok(())
}

#[test]
fn a_create_body_denies_network_and_stamps_the_namespace() -> Result<()> {
    let body = create_body("acme", &oci_spec()?)?;
    assert_eq!(body.template, "agent37-base");
    assert_eq!(body.network, Network::DenyAll);
    assert_eq!(
        body.metadata
            .get(NAMESPACE_METADATA_KEY)
            .map(String::as_str),
        Some("acme")
    );
    // The spec's default (2 cores / 2 GiB) snaps to agent37's smallest shape,
    // 2 vCPU / 4 GB — 2 GiB is not a shape agent37 offers.
    assert_eq!(
        body.resources,
        Some(InstanceResources {
            cpu: Some(2),
            memory: Some(4),
            disk: None,
        })
    );
    Ok(())
}

#[test]
fn unset_cpu_and_memory_map_to_none() {
    let resources = Resources {
        cpu_millis: 0,
        memory_bytes: 0,
        pids_max: 0,
        disk_bytes: 0,
    };
    assert!(instance_resources(&resources).is_none());
}

fn resources(cpu_millis: u32, memory_bytes: u64) -> Resources {
    Resources {
        cpu_millis,
        memory_bytes,
        pids_max: 0,
        disk_bytes: 0,
    }
}

#[test]
fn a_small_request_snaps_to_the_smallest_shape() {
    // 1 core / 1 GiB -> the smallest offered shape.
    assert_eq!(
        instance_resources(&resources(1_000, 1024 * 1024 * 1024)),
        Some(InstanceResources {
            cpu: Some(2),
            memory: Some(4),
            disk: None,
        })
    );
}

#[test]
fn extra_cores_force_a_four_core_shape_even_with_little_memory() {
    // 3 cores / 1 GiB: no 3-core shape, and 2 cores only pairs with 4 GB, so
    // the smallest covering shape is 4 vCPU / 8 GB.
    assert_eq!(
        instance_resources(&resources(3_000, 1024 * 1024 * 1024)),
        Some(InstanceResources {
            cpu: Some(4),
            memory: Some(8),
            disk: None,
        })
    );
}

#[test]
fn more_memory_than_a_small_shape_offers_climbs_to_a_larger_one() {
    // 2 cores / 10 GiB: needs >8 GB, so it climbs to 4 vCPU / 16 GB.
    assert_eq!(
        instance_resources(&resources(2_000, 10 * 1024 * 1024 * 1024)),
        Some(InstanceResources {
            cpu: Some(4),
            memory: Some(16),
            disk: None,
        })
    );
}

#[test]
fn a_request_beyond_every_shape_snaps_to_the_largest() {
    // 8 cores / 64 GiB exceeds the ceiling; cap at the largest shape.
    assert_eq!(
        instance_resources(&resources(8_000, 64 * 1024 * 1024 * 1024)),
        Some(InstanceResources {
            cpu: Some(4),
            memory: Some(32),
            disk: None,
        })
    );
}

#[test]
fn exec_body_shells_a_plain_command() {
    let body = exec_body(&ExecRequest::new(["echo", "hi"]));
    assert_eq!(body.command, "'echo' 'hi'");
}

#[test]
fn exec_body_single_quotes_cwd_env_and_args() {
    let mut request = ExecRequest::new(["sh", "-c", "it's ok"]);
    request.cwd = Some("/work dir".into());
    request.env.insert("KEY".to_owned(), "a b".to_owned());
    let body = exec_body(&request);
    // cd, then the env prefix, then the quoted argv; the embedded quote in
    // "it's ok" is escaped as '\''.
    assert_eq!(
        body.command,
        "cd '/work dir' && KEY='a b' 'sh' '-c' 'it'\\''s ok'"
    );
}

#[test]
fn exec_body_pipes_stdin_through_base64() {
    let request = ExecRequest::new(["cat"]).with_stdin(b"hi".to_vec());
    let body = exec_body(&request);
    // base64 of "hi" is "aGk="; it is decoded inside the instance and piped in.
    assert_eq!(body.command, "printf %s 'aGk=' | base64 -d | ( 'cat' )");
}

#[test]
fn exec_output_takes_plain_text_and_keeps_the_exit_code() {
    let result = ExecResult {
        exit_code: 3,
        stdout: "hi".to_owned(),
        stderr: String::new(),
        truncated: false,
    };
    let output = exec_output(&result);
    assert_eq!(output.exit_code, 3);
    assert_eq!(output.stdout, b"hi");
}

#[test]
fn statuses_map_to_states_and_unknown_is_failed() {
    assert_eq!(box_state_from_status("running"), BoxState::Ready);
    assert_eq!(box_state_from_status("Sleeping"), BoxState::Ready);
    assert_eq!(box_state_from_status("provisioning"), BoxState::Creating);
    assert_eq!(box_state_from_status("waking"), BoxState::Creating);
    assert_eq!(box_state_from_status("stopped"), BoxState::Stopped);
    assert_eq!(box_state_from_status("deleted"), BoxState::Archived);
    assert_eq!(box_state_from_status("who-knows"), BoxState::Failed);
}
