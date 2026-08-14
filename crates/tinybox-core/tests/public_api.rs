//! Consumer-perspective tests for the public API.
//!
//! These exercise only what is re-exported from the crate root, so they fail if
//! the export surface regresses even when the internals still compile.

use tinybox_core::{
    BoxSpec, BoxState, Capability, Error, ExecOutput, ExecRequest, HostRef, IsolationLevel,
    Lifecycle, NetworkPolicy, Placement, Resources, Result, SandboxCapabilities, SandboxRef,
    SnapshotId, SnapshotSupport, WorkspaceSource,
};

/// Build a placement, propagating identifier validation failures to the test.
fn placement(host: &str, sandbox: &str) -> Result<Placement> {
    Ok(Placement::new(
        HostRef::new(host)?,
        SandboxRef::new(sandbox)?,
    ))
}

#[test]
fn the_model_is_reachable_from_the_crate_root() -> Result<()> {
    let spec = BoxSpec::new(
        placement("local", "docker")?,
        WorkspaceSource::OciImage("alpine:3".to_owned()),
    );

    assert!(spec.validate().is_ok());
    assert!(spec.is_colocated());
    assert_eq!(spec.resources, Resources::DEFAULT);
    assert_eq!(spec.network, NetworkPolicy::Denied);
    assert!(spec.lifecycle.is_ephemeral());
    Ok(())
}

#[test]
fn reach_and_confinement_are_chosen_independently() -> Result<()> {
    let spec = BoxSpec::new(
        placement("builder-01", "docker")?,
        WorkspaceSource::Snapshot(SnapshotId::new("base-1")?),
    )
    .with_runner(placement("local", "passthrough")?)
    .with_lifecycle(Lifecycle::persistent());

    assert!(!spec.is_colocated());
    assert!(!spec.runner.shares_host(&spec.workspace));
    assert_eq!(spec.workspace.host.as_str(), "builder-01");
    assert!(spec.lifecycle.autosnapshot_interval().is_some());
    Ok(())
}

#[test]
fn a_backend_refuses_capabilities_it_does_not_declare() {
    let passthrough = SandboxCapabilities::PASSTHROUGH;

    assert_eq!(passthrough.isolation, IsolationLevel::None);
    assert!(!passthrough.is_suitable_for_untrusted_code());

    assert!(matches!(
        passthrough.require("passthrough", Capability::FilesystemSnapshot),
        Err(Error::Unsupported { .. })
    ));
}

#[test]
fn a_container_backend_snapshots_disk_but_not_memory() {
    let docker = SandboxCapabilities::new(
        IsolationLevel::Kernel,
        SnapshotSupport::Filesystem,
        true,
        false,
        true,
    );

    assert!(docker.is_suitable_for_untrusted_code());
    assert!(docker.supports(Capability::FilesystemSnapshot));
    assert!(!docker.supports(Capability::MemorySnapshot));
}

#[test]
fn invalid_input_is_rejected_at_the_boundary() -> Result<()> {
    assert!(HostRef::new("../escape").is_err());
    assert!(SandboxRef::new("").is_err());

    let outcome = BoxSpec::new(
        placement("local", "docker")?,
        WorkspaceSource::OciImage("alpine:3".to_owned()),
    )
    .with_resources(Resources {
        memory_bytes: 0,
        ..Resources::DEFAULT
    })
    .validate();

    assert!(matches!(
        outcome,
        Err(Error::ZeroResourceLimit {
            limit: "memory_bytes"
        })
    ));
    Ok(())
}

#[test]
fn commands_and_their_results_are_consumer_visible() {
    let request = ExecRequest::new(["cargo", "test"]).with_env("RUST_BACKTRACE", "1");
    assert_eq!(request.program(), Some("cargo"));

    let output = ExecOutput::new(0, b"ok".to_vec(), Vec::new());
    assert!(output.succeeded());
    assert_eq!(output.stdout_lossy(), "ok");

    assert!(BoxState::Ready.accepts_commands());
    assert!(!BoxState::Archived.is_live());
}
