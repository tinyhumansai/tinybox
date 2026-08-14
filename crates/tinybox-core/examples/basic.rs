//! Describe a box, and see what a backend will and will not agree to do.
//!
//! Run with `cargo run -p tinybox-core --example basic`.

use tinybox_core::{
    BoxSpec, Capability, HostRef, IsolationLevel, Lifecycle, NetworkPolicy, Placement, Resources,
    SandboxCapabilities, SandboxRef, SnapshotSupport, WorkspaceSource,
};

fn main() -> tinybox_core::Result<()> {
    // Reach and confinement are chosen independently, so this pairing needs no
    // code dedicated to "Docker over SSH" — it is just a host and a sandbox.
    let workspace = Placement::new(HostRef::new("builder-01")?, SandboxRef::new("docker")?);

    // The agent driving the work stays local while the code runs remotely.
    let runner = Placement::new(HostRef::new("local")?, SandboxRef::new("passthrough")?);

    let spec = BoxSpec::new(workspace, WorkspaceSource::OciImage("alpine:3".into()))
        .with_runner(runner)
        .with_resources(Resources {
            cpu_millis: 1_000,
            ..Resources::DEFAULT
        })
        .with_lifecycle(Lifecycle::persistent())
        .with_network(NetworkPolicy::Egress)
        .with_env("CI", "true");

    spec.validate()?;

    println!("runner:     {} / {}", spec.runner.host, spec.runner.sandbox);
    println!(
        "workspace:  {} / {}",
        spec.workspace.host, spec.workspace.sandbox
    );
    println!("colocated:  {}", spec.is_colocated());
    println!("autosnapshot: {:?}", spec.lifecycle.autosnapshot_interval());

    // A backend declares what it really does, and refuses the rest by name.
    let docker = SandboxCapabilities::new(IsolationLevel::Kernel, SnapshotSupport::Filesystem)
        .with_fork()
        .with_port_forward()
        .with_resource_limits();
    println!(
        "docker suits untrusted code: {}",
        docker.is_suitable_for_untrusted_code()
    );

    match docker.require("docker", Capability::MemorySnapshot) {
        Ok(()) => println!("docker captures live memory"),
        Err(error) => println!("refused: {error}"),
    }

    // Passthrough is honest about isolating nothing at all.
    let bare = SandboxCapabilities::PASSTHROUGH;
    println!(
        "passthrough suits untrusted code: {}",
        bare.is_suitable_for_untrusted_code()
    );

    Ok(())
}
