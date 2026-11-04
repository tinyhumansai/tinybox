//! A live end-to-end check of the agent37 backend against the real service.
//!
//! It creates one instance, runs `uname -s` in it, prints the result, and
//! deletes it. It is **not** a unit test: it needs a funded agent37 workspace
//! and a real key, so it is an example you run by hand, never part of
//! `cargo test`.
//!
//! ```sh
//! # with AGENT37_API_KEY exported (e.g. `set -a; . agent37.env; set +a`):
//! cargo run -p tinybox-agent37 --example live_smoke
//! ```
//!
//! It uses a 2 vCPU / 4 GB shape, one of agent37's valid shapes, and the
//! default `agent37-base` template. Deleting the instance ends its billing.

use std::sync::Arc;

use tinybox_agent37::{Agent37Sandbox, HttpTransport, api};
use tinybox_core::{
    BoxSpec, ExecRequest, HostRef, MemoryStore, NetworkPolicy, Placement, Sandbox, SandboxRef,
    WorkspaceSource,
};

/// The tinybox default spec (2 cores / 2 GiB) — deliberately *not* an agent37
/// shape, so `instance_resources` has to snap it up to `2 vCPU / 4 GB`.
fn smoke_spec() -> tinybox_core::Result<BoxSpec> {
    let mut spec = BoxSpec::new(
        Placement::new(HostRef::new("local")?, SandboxRef::new("agent37")?),
        WorkspaceSource::OciImage("agent37-base".to_owned()),
    );
    spec.network = NetworkPolicy::Denied;
    Ok(spec)
}

#[tokio::main]
async fn main() -> tinybox_core::Result<()> {
    let transport = HttpTransport::from_env()?;
    let backend = Agent37Sandbox::new(Arc::new(transport), Arc::new(MemoryStore::new()));

    let spec = smoke_spec()?;
    println!(
        "default spec resources {}m cpu / {} bytes mem snap to: {:?}",
        spec.resources.cpu_millis,
        spec.resources.memory_bytes,
        api::instance_resources(&spec.resources)
    );

    println!("creating an agent37 instance (template agent37-base)…");
    let info = backend.create(&spec).await?;
    println!("  created: id={} state={:?}", info.id.as_str(), info.state);

    println!("running `uname -s`…");
    let output = backend
        .exec(&info.id, &ExecRequest::new(["uname", "-s"]))
        .await?;
    println!(
        "  exit={} stdout={:?} stderr={:?}",
        output.exit_code,
        output.stdout_lossy(),
        output.stderr_lossy()
    );

    println!("destroying the instance…");
    backend.destroy(&info.id).await?;
    println!("  done");

    Ok(())
}
