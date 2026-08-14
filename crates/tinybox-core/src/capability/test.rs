//! Tests for capability declaration and enforcement.

use super::{Capability, IsolationLevel, SandboxCapabilities, SnapshotSupport};
use crate::error::Error;

/// A hypervisor-backed sandbox: everything available.
const MICROVM: SandboxCapabilities = SandboxCapabilities::new(
    IsolationLevel::Hardware,
    SnapshotSupport::FilesystemAndMemory,
    true,
    true,
    true,
);

/// A container sandbox: isolated and snapshottable, but no memory capture.
const CONTAINER: SandboxCapabilities = SandboxCapabilities::new(
    IsolationLevel::Kernel,
    SnapshotSupport::Filesystem,
    true,
    false,
    true,
);

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

    let process_only = SandboxCapabilities::new(
        IsolationLevel::Process,
        SnapshotSupport::None,
        false,
        false,
        false,
    );
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
}
