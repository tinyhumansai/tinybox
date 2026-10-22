//! Tests for [`ModuleStorage`]: host-backed records and fail-closed absence.

use super::*;
use tinybox_core::WorkspaceSource;
use tinybox_core::{
    BoxId, BoxInfo, BoxSpec, BoxState, HostRef, MemoryStore, Placement, SandboxRef,
};
use tinybus::broker::Broker;
use tinybus::transport::memory::MemoryBus;
use tinystoragedrivers_api::{DocumentStoreExt, StorageBackend};
use tinystoragedrivers_busproxy::{PerCallerEndpoint, ServedStorage, StorageServer, serve};
use tinystoragedrivers_testkit::MemoryBackend;
use tinystoragedrivers_types::{Query, Scope};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// A broker with a module-side connection and, optionally, a storage host.
struct Rig {
    module: Connection,
    backend: Arc<MemoryBackend>,
    _served: Option<ServedStorage>,
}

async fn rig(serve_storage: bool) -> Result<Rig, Box<dyn std::error::Error>> {
    let bus = MemoryBus::new();
    Broker::new().spawn(bus.clone());
    let backend = Arc::new(MemoryBackend::new());
    let host = Connection::connect(bus.connect().await?).await?;
    let served = if serve_storage {
        let bound = Arc::clone(&backend);
        let endpoint = PerCallerEndpoint::new(move |_sender| {
            let storage = bound.for_scope(&Scope::new("module/test").ok()?).ok()?;
            Some(StorageServer::new(storage))
        });
        Some(serve(&host, Arc::new(endpoint)).await?)
    } else {
        None
    };
    let module = Connection::connect(bus.connect().await?).await?;
    // Keep the host connection alive for the life of the broker.
    std::mem::forget(host);
    Ok(Rig {
        module,
        backend,
        _served: served,
    })
}

fn info(id: &str) -> Result<BoxInfo, Box<dyn std::error::Error>> {
    let spec = BoxSpec::new(
        Placement::new(HostRef::new("local")?, SandboxRef::new("passthrough")?),
        WorkspaceSource::LocalDir("/srv/work".into()),
    );
    Ok(BoxInfo::new(BoxId::new(id)?, BoxState::Ready, spec))
}

async fn host_docs(
    rig: &Rig,
    collection: &'static str,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let docs = Arc::clone(
        rig.backend
            .for_scope(&Scope::new("module/test")?)?
            .documents(),
    );
    let all = docs.query_all(collection, &Query::all()).await?;
    Ok(all.into_iter().map(|entry| entry.doc).collect())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn box_records_land_on_the_host_document_port() -> TestResult {
    let rig = rig(true).await?;
    let storage = ModuleStorage::connected(rig.module.clone());
    let store = storage.box_store().await?;
    let record = info("module-box-1")?;
    let writer = Arc::clone(&store);
    let written = record.clone();
    tokio::task::spawn_blocking(move || writer.insert(&written)).await??;

    let stored = host_docs(&rig, tinybox_drivers::BOX_COLLECTION).await?;
    assert_eq!(stored.len(), 1, "the record is a document on the host");
    let read = Arc::clone(&store);
    let listed = tokio::task::spawn_blocking(move || read.list()).await??;
    assert_eq!(listed, vec![record]);
    Ok(())
}

/// The module runs on one worker; a store call made directly from async code
/// must not wait on a bus reply that only that worker could deliver.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn store_calls_on_the_only_worker_do_not_deadlock() -> TestResult {
    let rig = rig(true).await?;
    let storage = ModuleStorage::connected(rig.module.clone());
    let store = storage.box_store().await?;
    let record = info("single-worker-box")?;
    tokio::time::timeout(std::time::Duration::from_secs(20), async {
        store.insert(&record)?;
        let listed = store.list()?;
        assert_eq!(listed, vec![record.clone()]);
        store.remove(&record.id)?;
        Ok::<(), tinybox_core::Error>(())
    })
    .await??;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_a_storage_host_box_records_fail_closed() -> TestResult {
    let rig = rig(false).await?;
    let storage = ModuleStorage::connected(rig.module.clone());
    assert!(storage.documents().await.is_none());
    assert!(storage.box_store().await.is_err());
    Ok(())
}

#[tokio::test]
async fn an_unconnected_module_has_no_documents() {
    let storage = ModuleStorage::default();
    assert!(storage.documents().await.is_none());
    assert!(
        storage
            .jail_registry(std::env::temp_dir(), "none".into())
            .await
            .is_none()
    );
    assert!(format!("{storage:?}").contains("connected: false"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_jail_index_is_a_document_on_the_host_not_a_file() -> TestResult {
    let rig = rig(true).await?;
    let storage = ModuleStorage::connected(rig.module.clone());
    let base = tempfile::tempdir()?;
    let registry = storage
        .jail_registry(base.path().to_path_buf(), "jails".into())
        .await
        .ok_or("host serves storage")??;
    let created = tokio::task::spawn_blocking(move || registry.create("scratch")).await??;

    assert!(
        !base.path().join("index.json").exists(),
        "no index file is written"
    );
    let stored = host_docs(&rig, tinybox_drivers::JAIL_INDEX_COLLECTION).await?;
    assert_eq!(stored.len(), 1);
    assert!(stored[0].to_string().contains(&created.id));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_connect_is_retried_when_the_host_starts_serving() -> TestResult {
    let bus = MemoryBus::new();
    Broker::new().spawn(bus.clone());
    let host = Connection::connect(bus.connect().await?).await?;
    let module = Connection::connect(bus.connect().await?).await?;
    let storage = ModuleStorage::connected(module);
    assert!(storage.documents().await.is_none());

    let backend = MemoryBackend::new();
    let endpoint = PerCallerEndpoint::new(move |_sender| {
        Some(StorageServer::new(
            backend.for_scope(&Scope::new("module/test").ok()?).ok()?,
        ))
    });
    let _served = serve(&host, Arc::new(endpoint)).await?;
    assert!(storage.documents().await.is_some());
    Ok(())
}

/// Every `Store` method forwards through the worker-safe wrapper.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn the_wrapper_forwards_get_and_set_state() -> TestResult {
    let rig = rig(true).await?;
    let storage = ModuleStorage::connected(rig.module.clone());
    let store = storage.box_store().await?;
    let record = info("forwarded-box")?;
    store.insert(&record)?;
    assert_eq!(store.get(&record.id)?, record);
    store.set_state(&record.id, BoxState::Stopped)?;
    assert_eq!(store.get(&record.id)?.state, BoxState::Stopped);
    Ok(())
}

/// Off a multi-thread runtime there is no worker to hand off, so the call runs
/// in place.
#[test]
fn the_wrapper_runs_in_place_without_a_multi_thread_runtime() -> TestResult {
    let store = OffWorkerStore(MemoryStore::new());
    let record = info("plain-box")?;
    store.insert(&record)?;
    assert_eq!(store.list()?, vec![record.clone()]);
    let runtime = tokio::runtime::Builder::new_current_thread().build()?;
    runtime.block_on(async {
        store.remove(&record.id)?;
        Ok::<(), tinybox_core::Error>(())
    })?;
    assert_eq!(store.list()?.len(), 0);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_scoped_handle_is_connected_once_and_shared() -> TestResult {
    let rig = rig(true).await?;
    let storage = ModuleStorage::connected(rig.module.clone());
    assert!(storage.documents().await.is_some());
    assert!(storage.documents().await.is_some());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unserved_host_does_not_provision_volatile_box_storage() -> TestResult {
    let bus = MemoryBus::new();
    Broker::new().spawn(bus.clone());
    let host = Connection::connect(bus.connect().await?).await?;
    let module = Connection::connect(bus.connect().await?).await?;
    let endpoint = PerCallerEndpoint::new(move |_sender| None::<StorageServer>);
    let _served = serve(&host, Arc::new(endpoint)).await?;
    let storage = ModuleStorage::connected(module);
    assert!(storage.documents().await.is_none());
    assert!(storage.box_store().await.is_err());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_host_backed_box_store_is_shared_by_every_resource() -> TestResult {
    let rig = rig(true).await?;
    let storage = ModuleStorage::connected(rig.module.clone());
    let first = storage.box_store().await?;
    let second = storage.box_store().await?;
    assert!(Arc::ptr_eq(&first, &second));
    Ok(())
}

/// Two resources share one collection; each finds only the record it wrote.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_recording_view_finds_only_its_own_record() -> TestResult {
    let shared: Arc<dyn Store> = Arc::new(MemoryStore::new());
    let first = RecordingStore::new(Arc::clone(&shared));
    let second = RecordingStore::new(Arc::clone(&shared));
    assert!(first.first_inserted().is_none());
    first.insert(&info("box-0")?)?;
    second.insert(&info("box-1")?)?;
    assert_eq!(first.first_inserted(), Some(BoxId::new("box-0")?));
    assert_eq!(second.first_inserted(), Some(BoxId::new("box-1")?));
    assert_eq!(second.list()?.len(), 2);
    second.set_state(&BoxId::new("box-1")?, BoxState::Stopped)?;
    assert_eq!(second.get(&BoxId::new("box-1")?)?.state, BoxState::Stopped);
    second.remove(&BoxId::new("box-1")?)?;
    assert!(second.first_inserted().is_none());
    assert!(first.insert(&info("box-0")?).is_err());
    // After a delete the id may be reissued to another resource; the view
    // that removed it must not claim the new holder's record.
    first.remove(&BoxId::new("box-0")?)?;
    second.insert(&info("box-0")?)?;
    assert!(first.first_inserted().is_none());
    Ok(())
}
