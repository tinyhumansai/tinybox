//! Loads a built module through the real `TinyBus` dynamic loader.

use std::io;
use std::path::PathBuf;
use std::time::Duration;

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
    // `Describe` is the module's only method, and it must at least name the
    // crate. Asserting the whole string would couple this verifier to the
    // registered-sandbox list, which changes as backends land.
    let description: String = proxy.call("Describe", ()).await?;
    if !description.starts_with("tinybox ") {
        return Err(io::Error::other(format!(
            "module returned an unexpected description: {description}"
        ))
        .into());
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
