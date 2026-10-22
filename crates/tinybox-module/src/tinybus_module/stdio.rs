//! One interactive jailed child with piped stdio, owned by the module.
//!
//! The child is spawned through the jail backend (never unconfined), leads its
//! own process group, and is reaped only by its waiter task. Output is pumped
//! into bounded per-stream buffers; a full buffer stops reading the pipe, which
//! backpressures the child instead of dropping bytes.
use super::resources::failure;
use std::collections::VecDeque;
use std::process::Child;
use std::sync::{Arc, Mutex as StdMutex};
use tinybox_bus::{
    MAX_STDIO_BUFFER_BYTES, MAX_STDIO_READ_BYTES, MAX_STDIO_WAIT_MS, STDIO_CLOSED, StdioChunk,
    StdioExit, StdioStartRequest, StdioStatus,
};
use tinybox_jail::{Jail, JailBackend};
use tinybus::Result;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::sync::Notify;

const REAP_POLL: std::time::Duration = std::time::Duration::from_millis(10);
const KILL_DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);

#[derive(Default)]
struct Buffers {
    stdout: VecDeque<u8>,
    stderr: VecDeque<u8>,
    stdout_eof: bool,
    stderr_eof: bool,
    exit: Option<StdioExit>,
}

#[derive(Default)]
struct Shared {
    buffers: StdMutex<Buffers>,
    changed: Notify,
}

impl Shared {
    fn lock(&self) -> std::sync::MutexGuard<'_, Buffers> {
        self.buffers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    /// Wait until `check` yields a value; every state change wakes it.
    async fn wait<T>(&self, mut check: impl FnMut(&mut Buffers) -> Option<T>) -> T {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if let Some(value) = check(&mut self.lock()) {
                return value;
            }
            changed.await;
        }
    }
}

#[derive(Clone, Copy)]
enum Pipe {
    Stdout,
    Stderr,
}

pub(super) struct StdioSession {
    request: StdioStartRequest,
    shared: Arc<Shared>,
    stdin: tokio::sync::Mutex<Option<tokio::process::ChildStdin>>,
    child: Arc<StdMutex<Option<Child>>>,
    group: i32,
    pumps: Vec<tokio::task::AbortHandle>,
}

impl StdioSession {
    /// Start `command` under `jail`. The caller has already run the jail
    /// preflight; spawn failures are reported without any weaker fallback.
    pub(super) async fn spawn(
        request: StdioStartRequest,
        backend: Arc<dyn JailBackend>,
        jail: Jail,
        mut command: std::process::Command,
    ) -> Result<Arc<Self>> {
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        let mut child = tokio::task::spawn_blocking(move || {
            tinybox_jail::spawn_captured_with(backend.as_ref(), &jail, command)
        })
        .await
        .map_err(|_| backend_failure("stdio start worker failed"))?
        .map_err(|error| {
            log::debug!(
                "[tinybox:stdio] jailed spawn failed kind={:?}",
                error.kind()
            );
            backend_failure("jailed stdio start failed")
        })?;
        let group = i32::try_from(child.id()).unwrap_or(0);
        let pipes = (|| {
            Some((
                tokio::process::ChildStdin::from_std(child.stdin.take()?).ok()?,
                tokio::process::ChildStdout::from_std(child.stdout.take()?).ok()?,
                tokio::process::ChildStderr::from_std(child.stderr.take()?).ok()?,
            ))
        })();
        let Some((stdin, stdout, stderr)) = pipes else {
            terminate(group, &mut child);
            reap_detached(child);
            return Err(backend_failure("stdio pipes unavailable"));
        };
        let shared = Arc::new(Shared::default());
        let child = Arc::new(StdMutex::new(Some(child)));
        let pumps = vec![
            tokio::spawn(pump(stdout, shared.clone(), Pipe::Stdout)).abort_handle(),
            tokio::spawn(pump(stderr, shared.clone(), Pipe::Stderr)).abort_handle(),
        ];
        tokio::spawn(reap(child.clone(), shared.clone(), group));
        log::debug!("[tinybox:stdio] started group={group}");
        Ok(Arc::new(Self {
            request,
            shared,
            stdin: tokio::sync::Mutex::new(Some(stdin)),
            child,
            group,
            pumps,
        }))
    }

    pub(super) fn request(&self) -> &StdioStartRequest {
        &self.request
    }

    pub(super) fn status(&self) -> StdioStatus {
        status_of(&self.shared.lock())
    }

    pub(super) async fn write(&self, data: &[u8]) -> Result<()> {
        // One deadline covers waiting behind earlier writes and the write.
        let deadline =
            tokio::time::Instant::now() + std::time::Duration::from_millis(MAX_STDIO_WAIT_MS);
        let Ok(mut guard) = tokio::time::timeout_at(deadline, self.stdin.lock()).await else {
            return Err(backend_failure("stdin is busy with an earlier write"));
        };
        let Some(stdin) = guard.as_mut() else {
            return Err(failure(STDIO_CLOSED, "stdin is closed"));
        };
        let write = async {
            stdin.write_all(data).await?;
            stdin.flush().await
        };
        if matches!(tokio::time::timeout_at(deadline, write).await, Ok(Ok(()))) {
            Ok(())
        } else {
            // A partial write leaves the framing unknown; close rather than
            // let the next write interleave with it.
            *guard = None;
            Err(failure(STDIO_CLOSED, "stdin write failed or timed out"))
        }
    }

    pub(super) async fn close_stdin(&self) {
        self.stdin.lock().await.take();
    }

    pub(super) async fn read(&self, max_bytes: u32, wait_ms: u64) -> StdioChunk {
        let max = match usize::try_from(max_bytes) {
            Ok(0) | Err(_) => MAX_STDIO_READ_BYTES,
            Ok(value) => value.min(MAX_STDIO_READ_BYTES),
        };
        let wait = std::time::Duration::from_millis(wait_ms.min(MAX_STDIO_WAIT_MS));
        let take = |buffers: &mut Buffers| {
            let ready = !buffers.stdout.is_empty()
                || !buffers.stderr.is_empty()
                || (buffers.stdout_eof && buffers.stderr_eof && buffers.exit.is_some());
            ready.then(|| drain(buffers, max))
        };
        let chunk = tokio::time::timeout(wait, self.shared.wait(take)).await;
        let chunk = chunk.unwrap_or_else(|_| drain(&mut self.shared.lock(), max));
        self.shared.changed.notify_waiters();
        chunk
    }

    /// Kill the whole process group and wait for the waiter to reap it.
    pub(super) async fn kill(&self) -> Result<()> {
        if let Some(child) = self
            .child
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_mut()
        {
            terminate(self.group, child);
        }
        self.stdin.lock().await.take();
        let reaped = self.shared.wait(|buffers| buffers.exit.map(|_| ()));
        tokio::time::timeout(KILL_DEADLINE, reaped)
            .await
            .map_err(|_| backend_failure("stdio child cleanup remains pending"))
    }
}

impl Drop for StdioSession {
    fn drop(&mut self) {
        let child = self
            .child
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(mut child) = child {
            terminate(self.group, &mut child);
            reap_detached(child);
        }
        for pump in &self.pumps {
            pump.abort();
        }
    }
}

fn backend_failure(message: &str) -> tinybus::Error {
    failure(tinybox_bus::BACKEND_ERROR, message)
}

fn status_of(buffers: &Buffers) -> StdioStatus {
    StdioStatus {
        running: buffers.exit.is_none(),
        exit: buffers.exit,
    }
}

fn drain(buffers: &mut Buffers, max: usize) -> StdioChunk {
    let out = max.min(buffers.stdout.len());
    let err = (max - out).min(buffers.stderr.len());
    let stdout: Vec<u8> = buffers.stdout.drain(..out).collect();
    let stderr: Vec<u8> = buffers.stderr.drain(..err).collect();
    StdioChunk {
        stdout,
        stderr,
        stdout_closed: buffers.stdout_eof && buffers.stdout.is_empty(),
        stderr_closed: buffers.stderr_eof && buffers.stderr.is_empty(),
        status: status_of(buffers),
    }
}

fn terminate(group: i32, child: &mut Child) {
    #[cfg(unix)]
    if group > 0 {
        use nix::{
            sys::signal::{Signal, killpg},
            unistd::Pid,
        };
        let _ = killpg(Pid::from_raw(group), Signal::SIGKILL);
    }
    #[cfg(not(unix))]
    let _ = group;
    let _ = child.kill();
}

/// A killed child still needs a wait to leave no zombie behind.
fn reap_detached(mut child: Child) {
    std::thread::spawn(move || {
        let _ = child.wait();
    });
}

async fn pump(mut pipe: impl AsyncRead + Unpin, shared: Arc<Shared>, which: Pipe) {
    let mut chunk = [0_u8; 8192];
    loop {
        // Read no more than the buffer has room for, so the bound is exact.
        let room = shared
            .wait(|buffers| {
                let held = match which {
                    Pipe::Stdout => buffers.stdout.len(),
                    Pipe::Stderr => buffers.stderr.len(),
                };
                (held < MAX_STDIO_BUFFER_BYTES).then_some(MAX_STDIO_BUFFER_BYTES - held)
            })
            .await;
        let take = room.min(chunk.len());
        match pipe.read(&mut chunk[..take]).await {
            Ok(0) | Err(_) => break,
            Ok(read) => {
                let mut buffers = shared.lock();
                match which {
                    Pipe::Stdout => buffers.stdout.extend(&chunk[..read]),
                    Pipe::Stderr => buffers.stderr.extend(&chunk[..read]),
                }
                drop(buffers);
                shared.changed.notify_waiters();
            }
        }
    }
    let mut buffers = shared.lock();
    match which {
        Pipe::Stdout => buffers.stdout_eof = true,
        Pipe::Stderr => buffers.stderr_eof = true,
    }
    drop(buffers);
    shared.changed.notify_waiters();
}

/// Sole reaper: record the exit, then kill what the child left behind so the
/// pipes reach end of file.
async fn reap(child: Arc<StdMutex<Option<Child>>>, shared: Arc<Shared>, group: i32) {
    loop {
        let waited = {
            let mut guard = child
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let Some(owned) = guard.as_mut() else { return };
            owned.try_wait()
        };
        match waited {
            Ok(None) => tokio::time::sleep(REAP_POLL).await,
            Ok(Some(status)) => {
                // Reaped: the id may be reused from now on, so nothing may
                // signal it through this session again (Kill, Drop).
                child
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .take();
                #[cfg(unix)]
                if group > 0 {
                    use nix::{
                        sys::signal::{Signal, killpg},
                        unistd::Pid,
                    };
                    let _ = killpg(Pid::from_raw(group), Signal::SIGKILL);
                }
                #[cfg(not(unix))]
                let _ = group;
                shared.lock().exit = Some(exit_of(status));
                shared.changed.notify_waiters();
                return;
            }
            Err(_) => {
                shared.lock().exit = Some(StdioExit::Unknown);
                shared.changed.notify_waiters();
                return;
            }
        }
    }
}

fn exit_of(status: std::process::ExitStatus) -> StdioExit {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return StdioExit::Signal(signal);
        }
    }
    status.code().map_or(StdioExit::Unknown, StdioExit::Code)
}

// The fixtures run `sh` and `head`, and the jail itself is Unix-only.
#[cfg(all(test, unix))]
#[path = "stdio_tests.rs"]
pub(super) mod tests;
