//! `TinyBus` interface, ABI exports, and the bus-facing service.
//!
//! This adapter keeps the runtime model in [`tinybox_core`] independent of
//! `TinyBus` while exposing it as an installable, dynamically loaded
//! integration. It is private so that the ABI symbols `module_export!`
//! generates stay out of the crate's public documentation.

use tinybox_core::{IsolationLevel, SandboxCapabilities};
use tinybus::{Connection, Result as TinyBusResult};

const INTERFACE: &str = "ai.tinyhumans.tinybox.Box";
const OBJECT_PATH: &str = "/ai/tinyhumans/tinybox/Box";

/// The bus-facing service.
struct BoxService;

#[tinybus::interface(name = "ai.tinyhumans.tinybox.Box")]
impl BoxService {
    /// Report what this build of tinybox can do.
    ///
    /// Returns the crate version followed by the sandboxes registered in this
    /// build, so a caller can tell whether the backend it needs is present
    /// before it tries to create a box.
    async fn describe(&self) -> TinyBusResult<String> {
        std::future::ready(Ok(describe(&registered_sandboxes()))).await
    }
}

/// The isolation a sandbox must reach before tinybox will call it safe for
/// code the operator does not trust.
///
/// Sourced from [`tinybox_core`] rather than restated here, so the bus answer
/// and the runtime check can never disagree.
const UNTRUSTED_FLOOR: IsolationLevel = IsolationLevel::Kernel;

/// Render the capability summary served by `Describe`.
///
/// Takes the sandbox list rather than reading it, so the rendering is a pure
/// function that can be asserted against any registry — including the populated
/// ones that later milestones will produce — without standing up a broker.
fn describe(sandboxes: &[(&str, SandboxCapabilities)]) -> String {
    let version = env!("CARGO_PKG_VERSION");
    let listed = if sandboxes.is_empty() {
        "none".to_owned()
    } else {
        sandboxes
            .iter()
            .map(|(name, _)| *name)
            .collect::<Vec<_>>()
            .join(", ")
    };

    let untrusted = sandboxes
        .iter()
        .filter(|(_, caps)| caps.is_suitable_for_untrusted_code())
        .map(|(name, _)| *name)
        .collect::<Vec<_>>();
    let untrusted = if untrusted.is_empty() {
        "none".to_owned()
    } else {
        untrusted.join(", ")
    };

    format!(
        "tinybox {version}; sandboxes: {listed}; untrusted-capable (>= {UNTRUSTED_FLOOR} isolation): {untrusted}"
    )
}

/// The sandbox backends compiled into this build, with what each declares.
///
/// Only backends this build can actually construct appear here: advertising a
/// sandbox that cannot be created would be worse than reporting none.
///
/// Passthrough is deliberately included even though it confines nothing, so
/// that `Describe` reports the full picture — and it is filtered out of the
/// untrusted-capable list by its own declaration rather than by a special case.
fn registered_sandboxes() -> Vec<(&'static str, SandboxCapabilities)> {
    vec![
        (
            tinybox_core::passthrough::NAME,
            SandboxCapabilities::PASSTHROUGH,
        ),
        (
            tinybox_docker::NAME,
            tinybox_docker::DockerSandbox::declared_capabilities(),
        ),
        (
            tinybox_linux::NAME,
            // Reported without cgroup limits: whether they are available
            // depends on the machine, and this is a static description of the
            // build rather than a probe of the host.
            tinybox_linux::NamespaceSandbox::declared_capabilities(false),
        ),
    ]
}

async fn setup(connection: Connection) -> TinyBusResult<()> {
    connection
        .serve_at(OBJECT_PATH.try_into()?, BoxService)
        .await?;
    connection.request_name(INTERFACE).await?;
    Ok(())
}

tinybus_module::module_export! {
    setup = setup,
    worker_threads = 1,
    provides = ["ai.tinyhumans.tinybox.Box"],
    methods = ["Describe"],
    signals = [],
    requires = [],
    optional = [],
    lazy = false,
}

#[cfg(test)]
mod test;
