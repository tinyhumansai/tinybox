//! Bounded output collection with a module-owned child supervisor.

use crate::LocalHost;
use async_trait::async_trait;
use std::path::Path;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use tinybox_core::{
    Error, ExecOutput, ExecRequest, ExecutionObserver, Forward, Host, OutputStream, Result,
    WorkspaceFileReader, WorkspaceFileWriter,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::sync::{oneshot, watch};

mod jailed;
mod process;
pub use jailed::JailLocalHost;
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

type RetainedChild = Arc<tokio::sync::Mutex<Option<process::NativeChild>>>;

#[derive(Debug)]
struct State {
    active: AtomicUsize,
    cleanup_failures: Mutex<std::collections::BTreeMap<i32, RetainedChild>>,
    cleanup_lock: tokio::sync::Mutex<()>,
    finished: watch::Sender<u64>,
}

// Preserve the native child if a provider/receiver panics inside the supervisor.
// Drop cannot acknowledge reaping; the normal drain path retries this handle.
struct RetainedOnDrop {
    child: Option<process::NativeChild>,
    group: i32,
    state: Arc<State>,
}
impl Drop for RetainedOnDrop {
    fn drop(&mut self) {
        if let Some(child) = self.child.take() {
            #[cfg(unix)]
            {
                let _ = nix::sys::signal::killpg(
                    nix::unistd::Pid::from_raw(self.group),
                    nix::sys::signal::Signal::SIGKILL,
                );
            }
            self.state
                .cleanup_failures
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(self.group, Arc::new(tokio::sync::Mutex::new(Some(child))));
        }
    }
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
        self.retry_retained_cleanup().await
    }

    async fn retry_retained_cleanup(&self) -> Result<()> {
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

impl LimitedLocalHost {
    /// Execute platform shell text with the ordinary output and cleanup supervisor.
    /// The request supplies cwd, environment and stdin; its argv is unused.
    ///
    /// # Errors
    /// Returns native startup, output-limit and cleanup errors just like observed argv execution.
    pub async fn run_shell_observed(
        &self,
        request: &ExecRequest,
        shell: &tinybox_bus::SelectShellRequest,
        observer: Arc<dyn ExecutionObserver>,
    ) -> Result<ExecOutput> {
        let mut command = crate::build_shell_command(shell);
        command.envs(&request.env);
        if let Some(cwd) = &request.cwd {
            command.current_dir(cwd);
        }
        command.stdin(if request.stdin.is_some() {
            std::process::Stdio::piped()
        } else {
            std::process::Stdio::null()
        });
        // Apply startup removals after provider/caller environment overrides.
        for name in crate::select_shell(shell).remove_environment {
            command.env_remove(name);
        }
        let mut command = tokio::process::Command::from(command);
        command.kill_on_drop(true);
        self.collect_command(command, request.stdin.clone(), Some(observer))
            .await
    }

    async fn collect(
        &self,
        request: &ExecRequest,
        observer: Option<Arc<dyn ExecutionObserver>>,
    ) -> Result<ExecOutput> {
        self.collect_command(
            LocalHost::command(request)?,
            request.stdin.clone(),
            observer,
        )
        .await
    }

    /// Collect a prepared native command with the same bounded ownership as argv execution.
    /// The provider supplies its approved environment and working directory.
    /// # Errors
    /// Reports spawn, pipe, output-budget and retained native cleanup failures.
    pub async fn run_command_observed(
        &self,
        command: std::process::Command,
        payload: Option<Vec<u8>>,
        observer: Arc<dyn ExecutionObserver>,
    ) -> Result<ExecOutput> {
        let mut command = tokio::process::Command::from(command);
        command.kill_on_drop(true).stdin(if payload.is_some() {
            std::process::Stdio::piped()
        } else {
            std::process::Stdio::null()
        });
        self.collect_command(command, payload, Some(observer)).await
    }

    async fn collect_command(
        &self,
        mut command: tokio::process::Command,
        payload: Option<Vec<u8>>,
        observer: Option<Arc<dyn ExecutionObserver>>,
    ) -> Result<ExecOutput> {
        process::prepare(&mut command)?;
        command
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let mut child =
            process::spawn_native(&mut command).map_err(|error| Error::io("spawn", &error))?;
        let group = match process::group(&child) {
            Ok(group) => group,
            Err(error) => {
                let _ = process::kill_unowned(&mut child).await;
                return Err(error);
            }
        };
        let stdout = pipe(process::take_stdout(&mut child), "stdout")?;
        let stderr = pipe(process::take_stderr(&mut child), "stderr")?;
        let stdin = process::take_stdin(&mut child);
        let budget = Arc::new(AtomicUsize::new(0));
        let limit = self.limit;
        let state = self.state.clone();
        state.active.fetch_add(1, Ordering::SeqCst);
        let (cancel, cancelled) = oneshot::channel::<()>();
        let supervisor = tokio::spawn(async move {
            let _active = Active(state.clone());
            let mut ownership = RetainedOnDrop {
                child: Some(child),
                group,
                state: state.clone(),
            };
            let child = ownership.child.as_mut().ok_or_else(|| Error::Backend {
                sandbox: crate::LOCAL.into(),
                operation: "own output collector",
                message: "missing native child".into(),
            })?;
            let collection =
                collect_until_exit(stdout, stderr, budget, limit, observer.clone(), async {
                    let ((), status) = tokio::try_join!(
                        async {
                            if let (Some(mut pipe), Some(payload)) = (stdin, payload) {
                                pipe.write_all(&payload)
                                    .await
                                    .map_err(|error| Error::io("write to stdin", &error))?;
                            }
                            Ok(())
                        },
                        async {
                            process::wait_native(child)
                                .await
                                .map_err(|error| Error::io("wait", &error))
                        }
                    )?;
                    Ok(status)
                });
            let result = tokio::select! {
                result = collection => result,
                () = observer_cancelled(observer.as_deref()) => Err(Error::Backend { sandbox: crate::LOCAL.into(), operation: "collect output", message: "execution cancelled".into() }),
                _ = cancelled => Err(Error::Backend { sandbox: crate::LOCAL.into(), operation: "collect output", message: "execution cancelled".into() }),
            };
            let child = ownership.child.take().ok_or_else(|| Error::Backend {
                sandbox: crate::LOCAL.into(),
                operation: "own output collector",
                message: "missing native child".into(),
            })?;
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
}

#[async_trait]
impl Host for LimitedLocalHost {
    fn name(&self) -> &'static str {
        crate::LOCAL
    }

    async fn run(&self, request: &ExecRequest) -> Result<ExecOutput> {
        self.collect(request, None).await
    }

    async fn run_observed(
        &self,
        request: &ExecRequest,
        observer: Arc<dyn ExecutionObserver>,
    ) -> Result<ExecOutput> {
        self.collect(request, Some(observer)).await
    }

    fn has_pending_observed_cleanup(&self) -> bool {
        self.has_pending_cleanup()
    }

    async fn retry_observed_cleanup(&self) -> Result<()> {
        self.retry_retained_cleanup().await
    }

    async fn forward(&self, remote: std::net::SocketAddr) -> Result<Forward> {
        LocalHost::new().forward(remote).await
    }

    async fn open_workspace_file(
        &self,
        root: &Path,
        relative: &Path,
    ) -> Result<Box<dyn WorkspaceFileReader>> {
        LocalHost::new().open_workspace_file(root, relative).await
    }

    async fn begin_workspace_file_write(
        &self,
        root: &Path,
        relative: &Path,
        transfer_id: &str,
    ) -> Result<Box<dyn WorkspaceFileWriter>> {
        LocalHost::new()
            .begin_workspace_file_write(root, relative, transfer_id)
            .await
    }
}

async fn cleanup(state: &State, mut child: process::NativeChild, group: i32) -> Result<()> {
    let result = process::terminate(&mut child, group).await;
    retain_cleanup(state, child, group, result)
}

fn retain_cleanup(
    state: &State,
    child: process::NativeChild,
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

async fn observer_cancelled(observer: Option<&dyn ExecutionObserver>) {
    match observer {
        Some(observer) => observer.cancelled().await,
        None => std::future::pending::<()>().await,
    }
}

#[cfg(test)]
async fn read(
    pipe: impl AsyncRead + Unpin,
    budget: Arc<AtomicUsize>,
    limit: usize,
) -> Result<Vec<u8>> {
    let bytes = Arc::new(std::sync::Mutex::new(Vec::new()));
    read_with_observer(
        pipe,
        budget,
        limit,
        OutputStream::Stdout,
        None,
        bytes.clone(),
    )
    .await?;
    let read = std::mem::take(
        &mut *bytes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
    );
    Ok(read)
}

/// Reads a command's stdout and stderr while `exited` (stdin delivery and the
/// wait for the process) runs, and returns once the process has exited and
/// both pipes have ended.
///
/// A process the command started in the background can hold the pipes open
/// after the command itself exits; waiting for their end would wait for that
/// process (a daemon start hung a call to its whole time limit). So once the
/// command has exited the pipes get [`OUTPUT_DRAIN_GRACE`] to end, and then
/// the output read so far is returned with [`OUTPUT_HELD_NOTE`] on stderr.
async fn collect_until_exit(
    stdout: impl AsyncRead + Unpin,
    stderr: impl AsyncRead + Unpin,
    budget: Arc<AtomicUsize>,
    limit: usize,
    observer: Option<Arc<dyn ExecutionObserver>>,
    exited: impl std::future::Future<Output = Result<std::process::ExitStatus>>,
) -> Result<ExecOutput> {
    let stdout_bytes = Arc::new(std::sync::Mutex::new(Vec::new()));
    let stderr_bytes = Arc::new(std::sync::Mutex::new(Vec::new()));
    let readers = async {
        tokio::try_join!(
            read_with_observer(
                stdout,
                budget.clone(),
                limit,
                OutputStream::Stdout,
                observer.clone(),
                stdout_bytes.clone(),
            ),
            read_with_observer(
                stderr,
                budget,
                limit,
                OutputStream::Stderr,
                observer,
                stderr_bytes.clone(),
            ),
        )
        .map(|_| ())
    };
    tokio::pin!(readers, exited);
    let mut drained = false;
    let status = tokio::select! {
        read = &mut readers => {
            read?;
            drained = true;
            (&mut exited).await?
        }
        status = &mut exited => status?,
    };
    let held = if drained {
        false
    } else {
        match tokio::time::timeout(OUTPUT_DRAIN_GRACE, &mut readers).await {
            Ok(read) => {
                read?;
                false
            }
            Err(_) => true,
        }
    };
    let take = |bytes: &std::sync::Mutex<Vec<u8>>| {
        std::mem::take(
            &mut *bytes
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    };
    let stdout = take(&stdout_bytes);
    let mut stderr = take(&stderr_bytes);
    if held {
        stderr.extend_from_slice(OUTPUT_HELD_NOTE.as_bytes());
    }
    Ok(ExecOutput::new(
        status.code().unwrap_or(128),
        stdout,
        stderr,
    ))
}

/// How long the output pipes may stay open after the command exits before
/// collection returns what it has read.
pub(crate) const OUTPUT_DRAIN_GRACE: std::time::Duration = std::time::Duration::from_secs(3);

/// Appended to stderr when the command exited but its output pipes stayed open.
pub(crate) const OUTPUT_HELD_NOTE: &str = "\n[tinybox] The command exited, but a process it \
     started still holds its output open; stopped reading after 3s. Redirect a background \
     process's output (`cmd > file 2>&1 &`) so the call returns at once.\n";

/// Reads `pipe` to its end into `bytes`, which keeps what was read if the
/// caller stops waiting first.
async fn read_with_observer(
    mut pipe: impl AsyncRead + Unpin,
    budget: Arc<AtomicUsize>,
    limit: usize,
    stream: OutputStream,
    observer: Option<Arc<dyn ExecutionObserver>>,
    bytes: Arc<std::sync::Mutex<Vec<u8>>>,
) -> Result<()> {
    let mut buffer = [0; 8192];
    loop {
        let count = pipe
            .read(&mut buffer)
            .await
            .map_err(|error| Error::io("read output", &error))?;
        if count == 0 {
            return Ok(());
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
        if let Some(observer) = &observer {
            observer.output(stream, &buffer[..count])?;
        }
        bytes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend_from_slice(&buffer[..count]);
    }
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;

#[cfg(all(test, unix))]
#[path = "observed_tests.rs"]
mod observed_tests;
