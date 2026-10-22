//! A bridge for the synchronous `TinyBox` model traits over async storage ports.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::mpsc as std_mpsc;
use std::thread;

use tinystoragedrivers_types::{Result, StorageError};
use tokio::sync::mpsc;

type Job = Pin<Box<dyn Future<Output = ()> + Send>>;

thread_local! {
    static ON_BRIDGE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Run port futures on a dedicated runtime thread for synchronous callers.
///
/// Calls made from a current-thread Tokio runtime fail rather than block that
/// runtime: host-backed ports may need its tasks to make progress. Callers on a
/// multithread runtime use Tokio's blocking handoff; calls outside Tokio wait
/// directly for the dedicated bridge thread.
#[derive(Clone)]
pub(crate) struct Blocking {
    jobs: mpsc::UnboundedSender<Job>,
}

impl fmt::Debug for Blocking {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Blocking").finish_non_exhaustive()
    }
}

impl Blocking {
    /// Start the runtime thread.
    pub(crate) fn new() -> Result<Self> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| startup_error("cannot build the storage bridge runtime", error))?;
        let (jobs, mut receiver) = mpsc::unbounded_channel::<Job>();
        thread::Builder::new()
            .name("tinybox-storage-bridge".into())
            .spawn(move || {
                ON_BRIDGE.with(|flag| flag.set(true));
                runtime.block_on(async move {
                    let mut running = tokio::task::JoinSet::new();
                    while let Some(job) = receiver.recv().await {
                        running.spawn(job);
                        while running.try_join_next().is_some() {}
                    }
                    while running.join_next().await.is_some() {}
                });
            })
            .map_err(|error| startup_error("cannot start the storage bridge thread", error))?;
        Ok(Self { jobs })
    }

    /// Run a port future and wait for its result.
    pub(crate) fn run<F, T>(&self, future: F) -> Result<T>
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        if ON_BRIDGE.with(std::cell::Cell::get) {
            return Err(StorageError::backend(
                "a storage bridge task called back into the same bridge",
            ));
        }
        if on_current_thread_runtime() {
            return Err(StorageError::backend(
                "synchronous storage calls are unavailable on a current-thread Tokio runtime",
            ));
        }
        let (reply, wait) = std_mpsc::sync_channel(1);
        self.jobs
            .send(Box::pin(async move {
                let _ = reply.send(future.await);
            }))
            .map_err(|_| StorageError::backend("the storage bridge has stopped"))?;
        let receive = || {
            wait.recv()
                .map_err(|_| StorageError::backend("the storage bridge dropped a call"))
        };
        if on_multi_thread_runtime() {
            tokio::task::block_in_place(receive)
        } else {
            receive()
        }
    }
}

fn on_multi_thread_runtime() -> bool {
    tokio::runtime::Handle::try_current()
        .is_ok_and(|handle| handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread)
}

fn on_current_thread_runtime() -> bool {
    tokio::runtime::Handle::try_current()
        .is_ok_and(|handle| handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::CurrentThread)
}

fn startup_error(message: &'static str, source: std::io::Error) -> StorageError {
    StorageError::backend(message).with_source(source)
}

#[cfg(test)]
#[path = "blocking_tests.rs"]
mod tests;
