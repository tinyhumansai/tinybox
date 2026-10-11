//! End-to-end proof for the compiled `TinyBox` module's workspace file contract.

use std::time::Duration;

use tinybox_bus::{
    BeginFileReadRequest, BeginFileWriteRequest, CreateRequest, FileChunk, FinishFileReadRequest,
    FinishFileWriteRequest, ReadFileChunkRequest, ReserveRequest, ResourceId, ResourceInfo,
    Workspace, WriteFileChunkRequest,
};
use tinybus::Connection;
use tinybus::broker::Broker;
use tinybus::module::{ModuleHost, ModuleState};
use tinybus::transport::memory::MemoryBus;

const BUS_NAME: &str = "ai.tinyhumans.tinybox.Box";
const OBJECT_PATH: &str = "/ai/tinyhumans/tinybox/Box";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TINYBOX_TEST_MODULE to point at the built cdylib"]
#[expect(
    clippy::too_many_lines,
    reason = "the compiled artifact proof keeps manifest, broker, transfer, and cleanup assertions in one fixture"
)]
async fn compiled_module_transfers_workspace_files_over_a_broker()
-> Result<(), Box<dyn std::error::Error>> {
    let artifact = std::env::var_os("TINYBOX_TEST_MODULE")
        .ok_or("TINYBOX_TEST_MODULE must point at libtinybox")?;
    let workspace = tempfile::tempdir()?;
    let input = workspace.path().join("source.bin");
    let output = workspace.path().join("nested/output.bin");
    let payload = (0_u8..=255).cycle().take(150_000).collect::<Vec<u8>>();
    std::fs::write(&input, &payload)?;

    let bus = MemoryBus::new();
    let broker = Broker::new();
    let broker_task = broker.spawn(bus.clone());
    let modules = ModuleHost::new(broker);
    let loaded = modules.load_file(artifact)?;
    assert_eq!(loaded.name, "tinybox-module");
    assert_eq!(loaded.manifest.bus_name.as_str(), BUS_NAME);
    assert_eq!(loaded.manifest.object_path.as_str(), OBJECT_PATH);
    let declared: Vec<&str> = loaded
        .manifest
        .provides
        .iter()
        .flat_map(|interface| interface.methods.iter())
        .map(tinybus::MemberName::as_str)
        .collect();
    assert_eq!(declared, tinybox_bus::METHODS);

    let client = Connection::connect(bus.connect().await?).await?;
    wait_until_serving(&client, &modules).await?;
    let proxy = client.proxy(BUS_NAME, OBJECT_PATH, BUS_NAME)?;
    let resource: ResourceId = proxy.call("Reserve", (ReserveRequest::Resource,)).await?;
    let created: ResourceInfo = proxy
        .call(
            "Create",
            (CreateRequest {
                resource: resource.clone(),
                backend: "passthrough".into(),
                workspace: Workspace::Directory(workspace.path().to_string_lossy().into_owned()),
                ..Default::default()
            },),
        )
        .await?;

    let reader: ResourceId = proxy
        .call("Reserve", (ReserveRequest::FileRead(resource.clone()),))
        .await?;
    let read_info: tinybox_bus::FileReadInfo = proxy
        .call(
            "BeginFileRead",
            (BeginFileReadRequest {
                resource: resource.clone(),
                transfer: reader.clone(),
                path: "source.bin".into(),
            },),
        )
        .await?;
    assert_eq!(read_info.size, payload.len() as u64);
    let mut offset = 0_u64;
    let writer: ResourceId = proxy
        .call("Reserve", (ReserveRequest::FileWrite(resource.clone()),))
        .await?;
    proxy
        .call::<tinybox_bus::FileWriteInfo>(
            "BeginFileWrite",
            (BeginFileWriteRequest {
                resource: resource.clone(),
                transfer: writer.clone(),
                path: "nested/output.bin".into(),
            },),
        )
        .await?;
    while offset < read_info.size {
        let chunk: FileChunk = proxy
            .call(
                "ReadFileChunk",
                (ReadFileChunkRequest {
                    resource: resource.clone(),
                    transfer: reader.clone(),
                    offset,
                    max_bytes: tinybox_bus::MAX_FILE_CHUNK_BYTES,
                },),
            )
            .await?;
        assert_eq!(chunk.offset, offset);
        assert_ne!(chunk.bytes, Vec::<u8>::new());
        let progress: tinybox_bus::FileWriteProgress = proxy
            .call(
                "WriteFileChunk",
                (WriteFileChunkRequest {
                    resource: resource.clone(),
                    transfer: writer.clone(),
                    offset,
                    bytes: chunk.bytes.clone(),
                },),
            )
            .await?;
        offset = offset
            .checked_add(chunk.bytes.len() as u64)
            .ok_or("transfer offset overflow")?;
        assert_eq!(progress.next_offset, offset);
    }
    proxy
        .call::<tinybox_bus::FileWriteProgress>(
            "FinishFileWrite",
            (FinishFileWriteRequest {
                resource: resource.clone(),
                transfer: writer,
            },),
        )
        .await?;
    proxy
        .call::<()>(
            "FinishFileRead",
            (FinishFileReadRequest {
                resource: resource.clone(),
                transfer: reader,
            },),
        )
        .await?;
    assert_eq!(std::fs::read(&output)?, payload);
    proxy.call::<()>("Close", (created.resource,)).await?;
    wait_until_idle(&modules).await?;
    broker_task.abort();
    Ok(())
}

async fn wait_until_serving(
    client: &Connection,
    modules: &ModuleHost,
) -> Result<(), Box<dyn std::error::Error>> {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if client
                .list_names()
                .await?
                .iter()
                .any(|name| name.as_str() == BUS_NAME)
            {
                return Ok::<(), tinybus::Error>(());
            }
            if modules
                .list()
                .first()
                .is_some_and(|module| matches!(module.state, ModuleState::Faulted { .. }))
            {
                return Err(tinybus::Error::failed(
                    "TinyBox module faulted during startup",
                ));
            }
            tokio::task::yield_now().await;
        }
    })
    .await??;
    Ok(())
}

async fn wait_until_idle(modules: &ModuleHost) -> Result<(), Box<dyn std::error::Error>> {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let state = modules
                .list()
                .first()
                .map(|module| module.state.clone())
                .ok_or_else(|| tinybus::Error::failed("loaded TinyBox module disappeared"))?;
            match state {
                ModuleState::Ready => return Ok::<(), tinybus::Error>(()),
                ModuleState::Serving => tokio::task::yield_now().await,
                _ => return Err(tinybus::Error::failed("TinyBox module left service")),
            }
        }
    })
    .await??;
    Ok(())
}
