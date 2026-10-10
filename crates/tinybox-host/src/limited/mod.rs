//! Bounded output collection with a module-owned child supervisor.

use crate::LocalHost;
use async_trait::async_trait;
use std::sync::{
    Arc,
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

#[derive(Debug)]
struct State {
    active: AtomicUsize,
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
        let group = process::group(&child)?;
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
            let _active = Active(state);
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
            process::terminate(&mut child, group).await?;
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
        if budget
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |used| {
                used.checked_add(count).filter(|total| *total <= limit)
            })
            .is_err()
        {
            return Err(Error::OutputLimitExceeded { limit });
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
