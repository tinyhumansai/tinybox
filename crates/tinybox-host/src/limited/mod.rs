//! Bounded output collection with a module-owned child supervisor.

use crate::LocalHost;
use async_trait::async_trait;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use tinybox_core::{Error, ExecOutput, ExecRequest, Forward, Host, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::sync::{oneshot, watch};

mod process;
pub use process::ManagedProcess;

/// A local host that caps combined stdout and stderr during collection.
///
/// Cancelling the caller signals an owned supervisor, which kills and reaps
/// the child. [`Self::drain`] waits for those supervisors before a resource
/// closes. The ordinary [`LocalHost`] retains its unbounded collection API.
#[derive(Debug, Clone)]
pub struct LimitedLocalHost {
    limit: usize,
    state: Arc<State>,
}

type RetainedChild = Arc<tokio::sync::Mutex<Option<tokio::process::Child>>>;

#[derive(Debug)]
struct State {
    active: AtomicUsize,
    cleanup_failures: Mutex<std::collections::BTreeMap<i32, RetainedChild>>,
    cleanup_lock: tokio::sync::Mutex<()>,
    finished: watch::Sender<u64>,
}

struct Active(Arc<State>);
impl Drop for Active {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::SeqCst);
        self.0
            .finished
            .send_modify(|generation| *generation = generation.wrapping_add(1));
    }
}

impl LimitedLocalHost {
    /// Collect at most `limit` bytes across both output streams.
    /// A zero budget permits commands that produce no output.
    #[must_use]
    pub fn new(limit: usize) -> Self {
        let (finished, _) = watch::channel(0);
        Self {
            limit,
            state: Arc::new(State {
                active: AtomicUsize::new(0),
                cleanup_failures: Mutex::new(std::collections::BTreeMap::new()),
                cleanup_lock: tokio::sync::Mutex::new(()),
                finished,
            }),
        }
    }

    /// Wait until every collected or cancelled child has been reaped.
    /// Only waits for operations already started on this host.
    pub async fn drain(&self) {
        let mut finished = self.state.finished.subscribe();
        while self.state.active.load(Ordering::SeqCst) != 0 {
            if finished.changed().await.is_err() {
                return;
            }
        }
    }
    /// Whether native children are retained after a cleanup failure.
    #[must_use]
    pub fn has_pending_cleanup(&self) -> bool {
        !self
            .state
            .cleanup_failures
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_empty()
    }

    /// Drain native supervisors and report any retained cleanup failure.
    ///
    /// # Errors
    /// A failed kill/reap retains its native child for a later public cleanup retry.
    pub async fn drain_checked(&self) -> Result<()> {
        self.drain().await;
        let _guard = self.state.cleanup_lock.lock().await;
        let groups: Vec<_> = self
            .state
            .cleanup_failures
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .keys()
            .copied()
            .collect();
        let mut failure = None;
        for group in groups {
            if let Err(error) = retry_cleanup_locked(&self.state, group).await {
                failure.get_or_insert(error);
            }
        }
        if let Some(error) = failure {
            return Err(error);
        }
        Ok(())
    }
}

#[async_trait]
impl Host for LimitedLocalHost {
    fn name(&self) -> &'static str {
        crate::LOCAL
    }

    async fn run(&self, request: &ExecRequest) -> Result<ExecOutput> {
        let mut command = LocalHost::command(request)?;
        process::prepare(&mut command)?;
        command
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let mut child = command
            .spawn()
            .map_err(|error| Error::io("spawn", &error))?;
        let group = match process::group(&child) {
            Ok(group) => group,
            Err(error) => {
                let _ = child.kill().await;
                return Err(error);
            }
        };
        let stdout = pipe(child.stdout.take(), "stdout")?;
        let stderr = pipe(child.stderr.take(), "stderr")?;
        let stdin = child.stdin.take();
        let payload = request.stdin.clone();
        let budget = Arc::new(AtomicUsize::new(0));
        let limit = self.limit;
        let state = self.state.clone();
        state.active.fetch_add(1, Ordering::SeqCst);
        let (cancel, cancelled) = oneshot::channel::<()>();
        let supervisor = tokio::spawn(async move {
            let _active = Active(state.clone());
            let collection = async {
                tokio::try_join!(
                    read(stdout, budget.clone(), limit),
                    read(stderr, budget, limit),
                    async {
                        if let (Some(mut pipe), Some(payload)) = (stdin, payload) {
                            pipe.write_all(&payload)
                                .await
                                .map_err(|error| Error::io("write to stdin", &error))?;
                        }
                        Ok(())
                    },
                    async {
                        child
                            .wait()
                            .await
                            .map_err(|error| Error::io("wait", &error))
                    }
                )
            };
            let result = tokio::select! {
                result = collection => result.map(|(stdout, stderr, (), status)| ExecOutput::new(status.code().unwrap_or(128), stdout, stderr)),
                _ = cancelled => Err(Error::Backend { sandbox: crate::LOCAL.into(), operation: "collect output", message: "execution cancelled".into() }),
            };
            cleanup(&state, child, group).await?;
            result
        });
        let result = supervisor.await.map_err(|error| Error::Backend {
            sandbox: crate::LOCAL.into(),
            operation: "collect output",
            message: error.to_string(),
        });
        drop(cancel);
        result?
    }

    async fn forward(&self, remote: std::net::SocketAddr) -> Result<Forward> {
        LocalHost::new().forward(remote).await
    }
}

async fn cleanup(state: &State, mut child: tokio::process::Child, group: i32) -> Result<()> {
    let result = process::terminate(&mut child, group).await;
    retain_cleanup(state, child, group, result)
}

fn retain_cleanup(
    state: &State,
    child: tokio::process::Child,
    group: i32,
    result: Result<()>,
) -> Result<()> {
    if result.is_err() {
        state
            .cleanup_failures
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(group, Arc::new(tokio::sync::Mutex::new(Some(child))));
    }
    result
}

async fn retry_cleanup(state: &State, group: i32) -> Result<()> {
    let _guard = state.cleanup_lock.lock().await;
    retry_cleanup_locked(state, group).await
}

async fn retry_cleanup_locked(state: &State, group: i32) -> Result<()> {
    let slot = state
        .cleanup_failures
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(&group)
        .cloned();
    let Some(slot) = slot else {
        return Ok(());
    };
    let mut slot = slot.lock().await;
    if let Some(child) = slot.as_mut() {
        // Ownership stays in the slot if a cleanup caller drops its future.
        process::terminate(child, group).await?;
    }
    slot.take();
    state
        .cleanup_failures
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .remove(&group);
    Ok(())
}

fn pipe<T>(value: Option<T>, stream: &str) -> Result<T> {
    value.ok_or_else(|| Error::Backend {
        sandbox: crate::LOCAL.into(),
        operation: "collect output",
        message: format!("missing {stream} pipe"),
    })
}

async fn read(
    mut pipe: impl AsyncRead + Unpin,
    budget: Arc<AtomicUsize>,
    limit: usize,
) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut buffer = [0; 8192];
    loop {
        let count = pipe
            .read(&mut buffer)
            .await
            .map_err(|error| Error::io("read output", &error))?;
        if count == 0 {
            return Ok(bytes);
        }
        let mut used = budget.load(Ordering::SeqCst);
        loop {
            let Some(total) = used.checked_add(count).filter(|total| *total <= limit) else {
                return Err(Error::OutputLimitExceeded { limit });
            };
            match budget.compare_exchange_weak(used, total, Ordering::SeqCst, Ordering::SeqCst) {
                Ok(_) => break,
                Err(actual) => used = actual,
            }
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
