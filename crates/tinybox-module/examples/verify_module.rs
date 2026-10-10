//! Loads a built module through the real `TinyBus` dynamic loader.

use std::io;
use std::path::PathBuf;
use std::time::Duration;

use tinybox_bus::{CreateRequest, ExecOutput, ExecRequest, ResourceInfo, ShellAnalysis, Workspace};
use tinybus::Connection;
use tinybus::broker::Broker;
use tinybus::module::ModuleHost;
use tinybus::transport::memory::MemoryBus;

const INTERFACE: &str = "ai.tinyhumans.tinybox.Box";
const OBJECT_PATH: &str = "/ai/tinyhumans/tinybox/Box";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let module = module_argument()?;
    let bus = MemoryBus::new();
    let broker = Broker::new();
    let broker_task = broker.spawn(bus.clone());
    let module_host = ModuleHost::new(broker);
    let info = module_host.load_file(&module)?;

    if info.name != env!("CARGO_PKG_NAME") {
        return Err(io::Error::other(format!(
            "loaded module `{}` instead of `{}`",
            info.name,
            env!("CARGO_PKG_NAME")
        ))
        .into());
    }

    let client = Connection::connect(bus.connect().await?).await?;
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let names = client.list_names().await?;
            if names.iter().any(|name| name.as_str() == INTERFACE) {
                return tinybus::Result::Ok(());
            }
            tokio::task::yield_now().await;
        }
    })
    .await??;

    let proxy = client.proxy(INTERFACE, OBJECT_PATH, INTERFACE)?;
    // `Describe` retains its original shape and must at least name the
    // crate. Asserting the whole string would couple this verifier to the
    // registered-sandbox list, which changes as backends land.
    let description: String = proxy.call("Describe", ()).await?;
    if !description.starts_with("tinybox ") {
        return Err(io::Error::other(format!(
            "module returned an unexpected description: {description}"
        ))
        .into());
    }

    // Exercise real resource ownership through the loaded native artifact.
    let analysis: ShellAnalysis = proxy
        .call("AnalyzeShell", ("echo hello".to_owned(),))
        .await?;
    if analysis.hidden_execution || analysis.redirection {
        return Err(io::Error::other("unexpected shell analysis").into());
    }
    let resource: ResourceInfo = proxy
        .call(
            "Create",
            (CreateRequest {
                resource: tinybox_bus::ResourceId("native-create".into()),
                backend: "passthrough".into(),
                workspace: Workspace::Directory(
                    std::env::current_dir()?.to_string_lossy().into_owned(),
                ),
                env: std::collections::BTreeMap::new(),
            },),
        )
        .await?;
    let inspected: ResourceInfo = proxy.call("Inspect", (resource.resource.clone(),)).await?;
    if resource != inspected {
        return Err(io::Error::other("resource inspection changed identity").into());
    }
    let request = ExecRequest {
        resource: resource.resource.clone(),
        argv: if cfg!(windows) {
            vec!["cmd".into(), "/C".into(), "echo tinybox-native".into()]
        } else {
            vec!["printf".into(), "tinybox-native".into()]
        },
        cwd: None,
        env: std::collections::BTreeMap::new(),
        stdin: None,
    };
    let output: ExecOutput = proxy.call("Exec", (request,)).await?;
    #[cfg(unix)]
    verify_detached(&proxy, &resource.resource).await?;
    proxy
        .call::<()>("Close", (resource.resource.clone(),))
        .await?;
    if output.exit_code != 0 || !String::from_utf8_lossy(&output.stdout).contains("tinybox-native")
    {
        return Err(io::Error::other("native module command failed").into());
    }
    if proxy
        .call::<ResourceInfo>("Inspect", (resource.resource,))
        .await
        .is_ok()
    {
        return Err(io::Error::other("closed resource remained usable").into());
    }

    println!(
        "verified {} as TinyBus module `{}`",
        module.display(),
        info.name
    );
    broker_task.abort();
    Ok(())
}

fn module_argument() -> Result<PathBuf, io::Error> {
    std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "usage: cargo run --example verify_module -- <module-path>",
            )
        })
}

#[cfg(unix)]
async fn verify_detached(
    proxy: &tinybus::Proxy,
    resource: &tinybox_bus::ResourceId,
) -> tinybus::Result<()> {
    let request = ExecRequest {
        resource: resource.clone(),
        argv: vec!["sleep".into(), "600".into()],
        cwd: None,
        env: std::collections::BTreeMap::new(),
        stdin: None,
    };
    let process: tinybox_bus::ProcessRef = proxy
        .call(
            "Spawn",
            (tinybox_bus::SpawnRequest {
                process: tinybox_bus::ResourceId("native-process-1".into()),
                command: request.clone(),
            },),
        )
        .await?;
    let running: bool = proxy.call("IsRunning", (process.clone(),)).await?;
    proxy.call::<()>("Cancel", (process.clone(),)).await?;
    let stopped: bool = proxy.call("IsRunning", (process,)).await?;
    if !running || stopped {
        return Err(tinybus::Error::failed("native process cancellation failed"));
    }
    // Leave another tracked workload for Close to clean up.
    let _: tinybox_bus::ProcessRef = proxy
        .call(
            "Spawn",
            (tinybox_bus::SpawnRequest {
                process: tinybox_bus::ResourceId("native-process-2".into()),
                command: request,
            },),
        )
        .await?;
    Ok(())
}
