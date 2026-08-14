//! Tests for capability declaration and enforcement.

use super::{Capability, IsolationLevel, SandboxCapabilities, SnapshotSupport};
use crate::error::Error;

/// A hypervisor-backed sandbox: everything available.
const MICROVM: SandboxCapabilities = SandboxCapabilities::new(
    IsolationLevel::Hardware,
    SnapshotSupport::FilesystemAndMemory,
)
.with_fork()
.with_pause_resume()
.with_port_forward()
.with_resource_limits();

/// A container sandbox: isolated and snapshottable, but no memory capture.
const CONTAINER: SandboxCapabilities =
    SandboxCapabilities::new(IsolationLevel::Kernel, SnapshotSupport::Filesystem)
        .with_fork()
        .with_port_forward()
        .with_resource_limits();

#[test]
fn passthrough_admits_it_isolates_nothing() {
    let caps = SandboxCapabilities::PASSTHROUGH;

    assert_eq!(caps.isolation, IsolationLevel::None);
    assert_eq!(caps.snapshot, SnapshotSupport::None);
    assert!(!caps.is_suitable_for_untrusted_code());
    assert!(!caps.supports(Capability::Fork));
    assert!(!caps.supports(Capability::PauseResume));
    assert!(!caps.supports(Capability::PortForward));
    assert!(!caps.supports(Capability::FilesystemSnapshot));
    assert!(!caps.supports(Capability::MemorySnapshot));
    assert!(!caps.supports(Capability::ResourceLimits));
}

#[test]
fn each_builder_method_adds_exactly_one_capability() {
    let base = SandboxCapabilities::new(IsolationLevel::Kernel, SnapshotSupport::None);

    assert!(base.declared().is_empty());
    assert_eq!(base.with_fork().declared(), [Capability::Fork]);
    assert_eq!(
        base.with_pause_resume().declared(),
        [Capability::PauseResume]
    );
    assert_eq!(
        base.with_port_forward().declared(),
        [Capability::PortForward]
    );
    assert_eq!(
        base.with_resource_limits().declared(),
        [Capability::ResourceLimits]
    );
}

#[test]
fn builders_accumulate_and_are_order_independent() {
    let base = SandboxCapabilities::new(IsolationLevel::Kernel, SnapshotSupport::None);

    assert_eq!(
        base.with_fork().with_port_forward(),
        base.with_port_forward().with_fork()
    );
    // Declaring the same capability twice is not an error and adds nothing.
    assert_eq!(base.with_fork().with_fork(), base.with_fork());
}

#[test]
fn a_sandbox_that_ignores_limits_declines_them() {
    // Accepting a memory cap and never applying it is the same class of
    // dishonesty as reporting isolation that does not exist.
    assert!(!SandboxCapabilities::PASSTHROUGH.supports(Capability::ResourceLimits));
    assert!(CONTAINER.supports(Capability::ResourceLimits));
    assert!(
        CONTAINER
            .require("docker", Capability::ResourceLimits)
            .is_ok()
    );

    assert!(
        SandboxCapabilities::PASSTHROUGH
            .require("passthrough", Capability::ResourceLimits)
            .err()
            .is_some_and(|error| error.to_string().contains("resource limits"))
    );
}

#[test]
fn a_declared_set_lists_snapshot_and_feature_capabilities_together() {
    // Snapshot support lives in its own field but must still surface as a
    // capability, or a caller asking "what can this do" would miss it.
    assert_eq!(
        CONTAINER.declared(),
        [
            Capability::FilesystemSnapshot,
            Capability::Fork,
            Capability::PortForward,
            Capability::ResourceLimits,
        ]
    );
    assert_eq!(MICROVM.declared(), Capability::ALL);
    assert!(SandboxCapabilities::PASSTHROUGH.declared().is_empty());
}

#[test]
fn capabilities_do_not_share_a_bit() {
    // Every feature capability must occupy its own bit, or declaring one would
    // silently grant another. Adding each in turn and checking the running set
    // grows by exactly one catches a duplicated shift.
    let mut built = SandboxCapabilities::new(IsolationLevel::None, SnapshotSupport::None);
    let mut expected = Vec::new();

    for (capability, add) in [
        (
            Capability::Fork,
            SandboxCapabilities::with_fork as fn(_) -> _,
        ),
        (
            Capability::PauseResume,
            SandboxCapabilities::with_pause_resume,
        ),
        (
            Capability::PortForward,
            SandboxCapabilities::with_port_forward,
        ),
        (
            Capability::ResourceLimits,
            SandboxCapabilities::with_resource_limits,
        ),
    ] {
        built = add(built);
        expected.push(capability);
        assert_eq!(built.declared(), expected);
    }
}

#[test]
fn require_names_the_sandbox_and_the_missing_capability() {
    let error = SandboxCapabilities::PASSTHROUGH
        .require("passthrough", Capability::Fork)
        .err();

    assert_eq!(
        error,
        Some(Error::Unsupported {
            sandbox: "passthrough".to_owned(),
            capability: Capability::Fork,
        })
    );
    assert!(
        error.is_some_and(
            |error| error.to_string() == "sandbox passthrough does not support forking"
        )
    );
}

#[test]
fn require_passes_for_a_declared_capability() {
    assert!(
        MICROVM
            .require("microvm", Capability::MemorySnapshot)
            .is_ok()
    );
    assert!(
        CONTAINER
            .require("docker", Capability::FilesystemSnapshot)
            .is_ok()
    );
}

#[test]
fn a_filesystem_sandbox_refuses_memory_snapshots() {
    assert!(CONTAINER.supports(Capability::FilesystemSnapshot));
    assert!(!CONTAINER.supports(Capability::MemorySnapshot));

    assert!(
        CONTAINER
            .require("docker", Capability::MemorySnapshot)
            .err()
            .is_some_and(|error| error.to_string().contains("memory snapshots"))
    );

    assert!(!CONTAINER.supports(Capability::PauseResume));
    assert!(CONTAINER.supports(Capability::PortForward));
    assert!(CONTAINER.supports(Capability::Fork));
}

#[test]
fn kernel_isolation_is_the_floor_for_untrusted_code() {
    assert!(!SandboxCapabilities::PASSTHROUGH.is_suitable_for_untrusted_code());
    assert!(CONTAINER.is_suitable_for_untrusted_code());
    assert!(MICROVM.is_suitable_for_untrusted_code());

    let process_only = SandboxCapabilities::new(IsolationLevel::Process, SnapshotSupport::None);
    assert!(!process_only.is_suitable_for_untrusted_code());
}

#[test]
fn isolation_levels_are_ordered_from_weakest_to_strongest() {
    assert!(IsolationLevel::None < IsolationLevel::Process);
    assert!(IsolationLevel::Process < IsolationLevel::Kernel);
    assert!(IsolationLevel::Kernel < IsolationLevel::Hardware);

    assert!(IsolationLevel::Hardware.is_at_least(IsolationLevel::Kernel));
    assert!(IsolationLevel::Kernel.is_at_least(IsolationLevel::Kernel));
    assert!(!IsolationLevel::Process.is_at_least(IsolationLevel::Kernel));
}

#[test]
fn snapshot_support_reports_what_it_captures() {
    assert!(!SnapshotSupport::None.captures_filesystem());
    assert!(!SnapshotSupport::None.captures_memory());

    assert!(SnapshotSupport::Filesystem.captures_filesystem());
    assert!(!SnapshotSupport::Filesystem.captures_memory());

    assert!(SnapshotSupport::FilesystemAndMemory.captures_filesystem());
    assert!(SnapshotSupport::FilesystemAndMemory.captures_memory());
}

#[test]
fn every_vocabulary_type_renders_for_error_messages() {
    assert_eq!(IsolationLevel::None.to_string(), "none");
    assert_eq!(IsolationLevel::Process.to_string(), "process");
    assert_eq!(IsolationLevel::Kernel.to_string(), "kernel");
    assert_eq!(IsolationLevel::Hardware.to_string(), "hardware");

    assert_eq!(SnapshotSupport::None.to_string(), "no snapshots");
    assert_eq!(
        SnapshotSupport::Filesystem.to_string(),
        "filesystem snapshots"
    );
    assert_eq!(
        SnapshotSupport::FilesystemAndMemory.to_string(),
        "filesystem and memory snapshots"
    );

    assert_eq!(
        Capability::FilesystemSnapshot.to_string(),
        "filesystem snapshots"
    );
    assert_eq!(Capability::MemorySnapshot.to_string(), "memory snapshots");
    assert_eq!(Capability::Fork.to_string(), "forking");
    assert_eq!(Capability::PauseResume.to_string(), "pause and resume");
    assert_eq!(Capability::PortForward.to_string(), "port forwarding");
    assert_eq!(Capability::ResourceLimits.to_string(), "resource limits");
}
