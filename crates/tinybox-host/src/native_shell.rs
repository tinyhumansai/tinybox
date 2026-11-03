//! Runtime-neutral orchestration for one supervised native shell execution.

use futures_util::{FutureExt, pin_mut, select};
use std::{
    future::Future,
    pin::Pin,
    time::{Duration, Instant},
};

use tinybox_bus::{
    CreateRequest, ExecutionFailure, ExecutionState, OutputBatch, OutputChunk, OutputStream,
    ProcessRef, ReserveRequest, ResourceId, ShellExecRequest,
};

/// Transport operations required to supervise a native shell.
///
/// Adapters implement these methods with their own bus connection and runtime.
pub trait NativeShellClient: Sync {
    /// Transport error returned by one bus operation.
    type Error;

    /// Reserve a resource or process identifier.
    fn reserve(
        &self,
        request: ReserveRequest,
    ) -> impl Future<Output = Result<ResourceId, Self::Error>> + Send;
    /// Create the resource with the module-issued reservation.
    fn create(
        &self,
        request: CreateRequest,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
    /// Start the requested native shell and return its owned process reference.
    fn start_native_shell_exec(
        &self,
        request: ShellExecRequest,
    ) -> impl Future<Output = Result<ProcessRef, Self::Error>> + Send;
    /// Read output starting at the supplied sequence cursor.
    fn read_output(
        &self,
        process: ProcessRef,
        cursor: u64,
    ) -> impl Future<Output = Result<OutputBatch, Self::Error>> + Send;
    /// Cancel and reap a running native process.
    fn cancel(&self, process: ProcessRef) -> impl Future<Output = Result<(), Self::Error>> + Send;
    /// Release retained output after the process reaches a terminal state.
    fn release_output(
        &self,
        process: ProcessRef,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
    /// Close the resource after process cleanup.
    fn close(&self, resource: ResourceId) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

/// Inputs for resource creation and native shell execution.
///
/// The `resource` and process reservation fields in `create` and `shell` are
/// replaced by identifiers reserved during the run.
#[derive(Debug, Clone)]
pub struct NativeShellRunRequest {
    /// Resource configuration; its reservation identifier is ignored.
    pub create: CreateRequest,
    /// Shell settings; its resource and process identifiers are ignored.
    pub shell: ShellExecRequest,
    /// Return a running process after this duration if it is shorter than the timeout.
    pub yield_after: Option<Duration>,
}

/// Collected native shell output after the module acknowledges process cleanup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeShellOutput {
    /// Process exit code, including nonzero exits.
    pub exit_code: i32,
    /// Complete stdout bytes.
    pub stdout: Vec<u8>,
    /// Complete stderr bytes.
    pub stderr: Vec<u8>,
    /// Whether the shell exceeded its request timeout.
    pub timed_out: bool,
}

/// Outcome of running a shell through `TinyBox`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeShellRunOutcome {
    /// The process exited or timed out and its output was released.
    Finished(NativeShellOutput),
    /// The process is still running; the caller now owns its cleanup lifecycle.
    Running(NativeShellRunning),
}

/// A running process handed back at the configured yield point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeShellRunning {
    /// Resource that must be closed after the process is finished.
    pub resource: ResourceId,
    /// Owned process reference for polling, cancellation, or release.
    pub process: ProcessRef,
    /// Cursor for the next output read.
    pub cursor: u64,
    /// Stdout collected before yielding.
    pub stdout: Vec<u8>,
    /// Stderr collected before yielding.
    pub stderr: Vec<u8>,
}

/// Failure during one phase of native shell orchestration.
#[derive(Debug)]
pub enum NativeShellError<E> {
    /// A bus operation failed.
    Transport {
        /// Human-readable operation that failed.
        operation: &'static str,
        /// Underlying adapter error.
        source: E,
    },
    /// The module reported a terminal failed state.
    Execution(ExecutionFailure),
    /// An output batch did not continue exactly at the cursor: a replayed or
    /// skipped chunk, or a next sequence that disagrees with its chunks.
    InvalidOutputCursor,
    /// Cancellation failed, so native cleanup is not acknowledged.
    Cancellation(E),
    /// Output release failed after the process had stopped.
    OutputRelease(E),
    /// Resource close failed after process cleanup.
    ResourceClose(E),
    /// Cleanup failed while another operation was already failing.
    Cleanup {
        /// Cleanup operation that failed.
        operation: &'static str,
        /// Cleanup adapter error.
        source: E,
        /// Earlier failure that led to cleanup.
        during: Box<Self>,
    },
}

/// Run one native shell and stream every output chunk to `on_chunk`.
///
/// The caller must keep this future supervised while signaling `cancelled`;
/// dropping it cannot await native process cleanup. The helper reserves and
/// creates the resource, starts the process, polls replayable output, cancels
/// on timeout or caller cancellation, releases output, and closes the resource.
///
/// # Errors
/// Returns the transport failure, module execution failure, or cleanup failure.
pub async fn run_native_shell<C, F, Fut>(
    client: &C,
    request: NativeShellRunRequest,
    cancelled: Fut,
    mut on_chunk: F,
) -> Result<NativeShellRunOutcome, NativeShellError<C::Error>>
where
    C: NativeShellClient,
    F: FnMut(&OutputChunk),
    Fut: Future<Output = ()> + Send,
    F: Send,
    C::Error: Send,
{
    let timeout_ms = request.shell.timeout_ms.max(1);
    let yield_after = request
        .yield_after
        .filter(|after| *after < Duration::from_millis(timeout_ms));
    let yield_started = Instant::now();
    let resource = client
        .reserve(ReserveRequest::Resource)
        .await
        .map_err(|source| NativeShellError::Transport {
            operation: "reserve resource",
            source,
        })?;
    let mut shell = request.shell;
    shell.timeout_ms = timeout_ms;
    let result = async {
        let process = start_native_shell(client, resource.clone(), request.create, shell).await?;
        collect_native_shell(
            client,
            process,
            NativeShellCollectionConfig {
                resource: resource.clone(),
                timeout_ms,
                yield_after,
                yield_started,
            },
            cancelled,
            &mut on_chunk,
        )
        .await
    }
    .await;
    let result = match result {
        Ok(NativeShellRunOutcome::Running(running)) => {
            return Ok(NativeShellRunOutcome::Running(running));
        }
        result => result,
    };
    let close_result = client.close(resource).await;
    match (result, close_result) {
        (Ok(output), Ok(())) => Ok(output),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(source)) => Err(NativeShellError::ResourceClose(source)),
        (Err(error), Err(source)) => Err(NativeShellError::Cleanup {
            operation: "close resource",
            source,
            during: Box::new(error),
        }),
    }
}

async fn start_native_shell<C: NativeShellClient>(
    client: &C,
    resource: ResourceId,
    mut create: CreateRequest,
    mut shell: ShellExecRequest,
) -> Result<ProcessRef, NativeShellError<C::Error>> {
    create.resource = resource.clone();
    client
        .create(create)
        .await
        .map_err(|source| NativeShellError::Transport {
            operation: "create resource",
            source,
        })?;
    let process_id = client
        .reserve(ReserveRequest::Process(resource.clone()))
        .await
        .map_err(|source| NativeShellError::Transport {
            operation: "reserve process",
            source,
        })?;
    shell.resource = resource;
    shell.process = process_id;
    client
        .start_native_shell_exec(shell)
        .await
        .map_err(|source| NativeShellError::Transport {
            operation: "start native shell",
            source,
        })
}

async fn collect_native_shell<C, F, Fut>(
    client: &C,
    process: ProcessRef,
    config: NativeShellCollectionConfig,
    cancelled: Fut,
    on_chunk: &mut F,
) -> Result<NativeShellRunOutcome, NativeShellError<C::Error>>
where
    C: NativeShellClient,
    F: FnMut(&OutputChunk),
    Fut: Future<Output = ()> + Send,
    F: Send,
    C::Error: Send,
{
    let deadline = Instant::now() + Duration::from_millis(config.timeout_ms);
    let mut capture = NativeShellCapture::default();
    let cancelled = cancelled.fuse();
    pin_mut!(cancelled);
    let mut cancellation_requested = false;
    let mut timed_out = false;
    loop {
        let poll = next_native_shell_batch(
            client,
            &process,
            capture.cursor,
            deadline,
            cancellation_requested,
            cancelled.as_mut(),
        )
        .await?;
        match poll {
            NativeShellPoll::Cancelled => {
                cancellation_requested = true;
            }
            NativeShellPoll::TimedOut => {
                cancellation_requested = true;
                timed_out = true;
            }
            NativeShellPoll::Batch(batch) => {
                let has_chunks = !batch.chunks.is_empty();
                if !capture.append(&batch, on_chunk) {
                    let primary = NativeShellError::InvalidOutputCursor;
                    if let Err(source) = client.cancel(process.clone()).await {
                        return Err(NativeShellError::Cleanup {
                            operation: "cancel after invalid output cursor",
                            source,
                            during: Box::new(primary),
                        });
                    }
                    if let Err(source) = client.release_output(process.clone()).await {
                        return Err(NativeShellError::Cleanup {
                            operation: "release output after invalid cursor",
                            source,
                            during: Box::new(primary),
                        });
                    }
                    return Err(primary);
                }
                if has_chunks && !matches!(&batch.state, ExecutionState::Running) {
                    continue;
                }
                if let Some(output) =
                    finish_native_shell(client, &process, &mut capture, batch.state, timed_out)
                        .await?
                {
                    return Ok(NativeShellRunOutcome::Finished(output));
                }
                if !cancellation_requested
                    && config
                        .yield_after
                        .is_some_and(|after| config.yield_started.elapsed() >= after)
                {
                    return Ok(NativeShellRunOutcome::Running(NativeShellRunning {
                        resource: config.resource,
                        process,
                        cursor: capture.cursor,
                        stdout: capture.stdout,
                        stderr: capture.stderr,
                    }));
                }
            }
        }
    }
}

async fn finish_native_shell<C: NativeShellClient>(
    client: &C,
    process: &ProcessRef,
    capture: &mut NativeShellCapture,
    state: ExecutionState,
    timed_out: bool,
) -> Result<Option<NativeShellOutput>, NativeShellError<C::Error>> {
    let output = match state {
        ExecutionState::Running => return Ok(None),
        ExecutionState::Exited { exit_code } => capture.finish(exit_code, timed_out),
        ExecutionState::Cancelled => capture.finish(-1, timed_out),
        ExecutionState::Failed {
            code: ExecutionFailure::TimedOut,
        } => capture.finish(-1, true),
        ExecutionState::Failed { code } => {
            client
                .release_output(process.clone())
                .await
                .map_err(NativeShellError::OutputRelease)?;
            return Err(NativeShellError::Execution(code));
        }
    };
    client
        .release_output(process.clone())
        .await
        .map_err(NativeShellError::OutputRelease)?;
    Ok(Some(output))
}

struct NativeShellCollectionConfig {
    resource: ResourceId,
    timeout_ms: u64,
    yield_after: Option<Duration>,
    yield_started: Instant,
}

#[derive(Default)]
struct NativeShellCapture {
    cursor: u64,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl NativeShellCapture {
    fn append<F>(&mut self, batch: &OutputBatch, on_chunk: &mut F) -> bool
    where
        F: FnMut(&OutputChunk),
    {
        // Chunks must continue exactly at the cursor, with no replay or gap.
        let contiguous = batch
            .chunks
            .iter()
            .zip(self.cursor..)
            .all(|(chunk, sequence)| chunk.sequence == sequence);
        if !contiguous || batch.next_sequence != self.cursor + batch.chunks.len() as u64 {
            return false;
        }
        for chunk in &batch.chunks {
            on_chunk(chunk);
            match chunk.stream {
                OutputStream::Stdout => self.stdout.extend_from_slice(&chunk.bytes),
                OutputStream::Stderr => self.stderr.extend_from_slice(&chunk.bytes),
            }
        }
        self.cursor = batch.next_sequence;
        true
    }

    fn finish(&mut self, exit_code: i32, timed_out: bool) -> NativeShellOutput {
        NativeShellOutput {
            exit_code,
            stdout: std::mem::take(&mut self.stdout),
            stderr: std::mem::take(&mut self.stderr),
            timed_out,
        }
    }
}

enum NativeShellPoll {
    Batch(OutputBatch),
    Cancelled,
    TimedOut,
}

async fn next_native_shell_batch<C, Fut>(
    client: &C,
    process: &ProcessRef,
    cursor: u64,
    deadline: Instant,
    cancellation_requested: bool,
    mut cancelled: Pin<&mut futures_util::future::Fuse<Fut>>,
) -> Result<NativeShellPoll, NativeShellError<C::Error>>
where
    C: NativeShellClient,
    C::Error: Send,
    Fut: Future<Output = ()> + Send,
{
    let remaining = deadline.saturating_duration_since(Instant::now());
    let poll = client.read_output(process.clone(), cursor).fuse();
    let delay = futures_timer::Delay::new(if cancellation_requested {
        Duration::from_millis(20)
    } else {
        remaining.min(Duration::from_millis(20))
    })
    .fuse();
    pin_mut!(poll, delay);
    if cancellation_requested {
        select! {
            result = poll => result
                .map(NativeShellPoll::Batch)
                .map_err(|source| NativeShellError::Transport { operation: "read output", source }),
        }
    } else {
        select! {
            result = poll => match result {
                Ok(batch) => Ok(NativeShellPoll::Batch(batch)),
                Err(source) => {
                    client.cancel(process.clone()).await.map_err(NativeShellError::Cancellation)?;
                    client.release_output(process.clone()).await.map_err(NativeShellError::OutputRelease)?;
                    Err(NativeShellError::Transport { operation: "read output", source })
                }
            },
            () = cancelled => {
                client.cancel(process.clone()).await.map_err(NativeShellError::Cancellation)?;
                Ok(NativeShellPoll::Cancelled)
            },
            () = delay => {
                client.cancel(process.clone()).await.map_err(NativeShellError::Cancellation)?;
                Ok(NativeShellPoll::TimedOut)
            }
        }
    }
}

#[cfg(test)]
#[path = "native_shell_tests.rs"]
mod tests;
