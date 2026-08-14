//! Tests for the `TinyBus` module adapter and its declared surface.

use super::{BoxService, INTERFACE, OBJECT_PATH, describe, registered_sandboxes, setup};
use tinybox_core::{IsolationLevel, SandboxCapabilities, SnapshotSupport};
use tinybus::broker::Broker;
use tinybus::transport::memory::MemoryBus;
use tinybus::{Connection, Interface};

/// A container-class backend, standing in for one a later milestone registers.
const CONTAINER: SandboxCapabilities = SandboxCapabilities::new(
    IsolationLevel::Kernel,
    SnapshotSupport::Filesystem,
    true,
    false,
    true,
);

/// A backend too weak to be trusted with untrusted code.
const BARE: SandboxCapabilities = SandboxCapabilities::PASSTHROUGH;

#[test]
fn declared_methods_match_the_dispatch_table() {
    let methods = BoxService
        .members()
        .into_iter()
        .map(|member| member.to_string())
        .collect::<Vec<_>>();

    assert_eq!(methods, ["Describe"]);
}

#[test]
fn an_empty_registry_is_reported_as_none_rather_than_omitted() {
    // No backends are compiled in yet, and the module says so plainly rather
    // than leaving the reader to infer it from an absent list.
    assert!(registered_sandboxes().is_empty());

    let description = describe(&registered_sandboxes());

    assert!(description.contains(env!("CARGO_PKG_VERSION")));
    assert!(description.contains("kernel"));
    assert!(description.contains("sandboxes: none"));
    assert!(description.contains("untrusted-capable"));
    assert!(description.ends_with("none"));
}

#[test]
fn a_populated_registry_lists_every_sandbox() {
    let description = describe(&[("docker", CONTAINER), ("namespace", CONTAINER)]);

    assert!(description.contains("sandboxes: docker, namespace"));
    assert!(description.ends_with("docker, namespace"));
}

#[test]
fn only_sandboxes_above_the_isolation_floor_are_called_untrusted_capable() {
    let description = describe(&[("passthrough", BARE), ("docker", CONTAINER)]);

    // Both are listed as present...
    assert!(description.contains("sandboxes: passthrough, docker"));
    // ...but only the one that actually confines anything is recommended.
    assert!(description.ends_with("docker"));
    assert!(!description.ends_with("passthrough, docker"));
}

#[test]
fn a_registry_of_only_weak_sandboxes_recommends_nothing() {
    let description = describe(&[("passthrough", BARE)]);

    assert!(description.contains("sandboxes: passthrough"));
    assert!(description.ends_with("none"));
}

#[tokio::test]
async fn module_describes_itself_over_a_real_bus() -> tinybus::Result<()> {
    let bus = MemoryBus::new();
    Broker::new().spawn(bus.clone());

    let service = Connection::connect(bus.connect().await?).await?;
    setup(service.clone()).await?;

    let client = Connection::connect(bus.connect().await?).await?;
    let proxy = client.proxy(INTERFACE, OBJECT_PATH, INTERFACE)?;
    let description: String = proxy.call("Describe", ()).await?;

    assert_eq!(description, describe(&registered_sandboxes()));
    Ok(())
}

#[tokio::test]
async fn the_module_claims_its_well_known_name() -> tinybus::Result<()> {
    let bus = MemoryBus::new();
    Broker::new().spawn(bus.clone());

    let service = Connection::connect(bus.connect().await?).await?;
    setup(service.clone()).await?;

    let client = Connection::connect(bus.connect().await?).await?;
    let names = client.list_names().await?;

    assert!(
        names.iter().any(|name| name.as_str() == INTERFACE),
        "expected {INTERFACE} among {names:?}"
    );
    Ok(())
}

#[tokio::test]
async fn an_unknown_method_is_rejected() -> tinybus::Result<()> {
    let bus = MemoryBus::new();
    Broker::new().spawn(bus.clone());

    let service = Connection::connect(bus.connect().await?).await?;
    setup(service.clone()).await?;

    let client = Connection::connect(bus.connect().await?).await?;
    let proxy = client.proxy(INTERFACE, OBJECT_PATH, INTERFACE)?;
    let result = proxy.call::<String>("Snapshot", ()).await;

    assert!(
        result.is_err(),
        "a method outside the declared surface should be refused"
    );
    Ok(())
}
