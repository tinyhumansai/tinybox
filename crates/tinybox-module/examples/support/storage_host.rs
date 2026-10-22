//! Host-backed test storage used by the compiled-module verifiers.

use std::sync::Arc;

use tinybus::{Connection, transport::memory::MemoryBus};
use tinystoragedrivers_api::StorageBackend;
use tinystoragedrivers_busproxy::{PerCallerEndpoint, ServedStorage, StorageServer};
use tinystoragedrivers_testkit::MemoryBackend;
use tinystoragedrivers_types::Scope;

/// Keeps the real testkit storage host and its bus registration alive.
pub(crate) struct ServedTestStorage {
    _host: Connection,
    _served: ServedStorage,
}

/// Serve a real TSD storage endpoint before a module is admitted and started.
pub(crate) async fn serve(
    bus: &MemoryBus,
) -> Result<ServedTestStorage, Box<dyn std::error::Error>> {
    let backend = Arc::new(MemoryBackend::new());
    let host = Connection::connect(bus.connect().await?).await?;
    let bound = Arc::clone(&backend);
    let endpoint = PerCallerEndpoint::new(move |_sender| {
        let scope = Scope::new("tinybox/module-verifier").ok()?;
        let storage = bound.for_scope(&scope).ok()?;
        Some(StorageServer::new(storage))
    });
    let served = tinystoragedrivers_busproxy::serve(&host, Arc::new(endpoint)).await?;
    Ok(ServedTestStorage {
        _host: host,
        _served: served,
    })
}
