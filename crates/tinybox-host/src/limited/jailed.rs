//! Bounded collection of standard-library children created by native jail backends.
use super::{collect_until_exit, observer_cancelled, pipe};
use async_trait::async_trait;
use std::collections::BTreeMap;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use tinybox_core::{Error, ExecOutput, ExecRequest, ExecutionObserver, Host, Result};
use tinybox_jail::{Jail, JailBackend, OwnedChild};
use tokio::io::AsyncWriteExt;
#[cfg(unix)]
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{oneshot, watch};

#[cfg(target_os = "linux")]
const CPU_EVENT_FILE_ENV: &str = "TINYBOX_INTERNAL_CPU_EVENT_FILE";
#[cfg(target_os = "linux")]
static CPU_EVENT_FILE_SEQUENCE: AtomicUsize = AtomicUsize::new(1);

#[cfg(target_os = "linux")]
struct CpuEventReport(std::path::PathBuf);

#[cfg(target_os = "linux")]
impl CpuEventReport {
    fn prepare(
        command: &std::process::Command,
        env: &mut BTreeMap<String, String>,
    ) -> Option<Self> {
        let runtime_dir = std::env::var_os("XDG_RUNTIME_DIR")?;
        Self::prepare_in(command, env, std::path::Path::new(&runtime_dir))
    }

    fn prepare_in(
        command: &std::process::Command,
        env: &mut BTreeMap<String, String>,
        runtime_dir: &std::path::Path,
    ) -> Option<Self> {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

        let runtime_dir = runtime_dir.canonicalize().ok()?;
        if !runtime_dir.starts_with("/run/") {
            return None;
        }
        let args: Vec<_> = command.get_args().filter_map(|arg| arg.to_str()).collect();
        let has_scope = args.iter().any(|arg| {
            arg.strip_prefix("--unit=")
                .and_then(|unit| std::path::Path::new(unit).extension())
                .is_some_and(|extension| extension.eq_ignore_ascii_case("scope"))
                && arg.starts_with("--unit=tinybox-native-")
        });
        let has_cpu_limit = args
            .iter()
            .any(|arg| arg.starts_with("--property=CPUQuota="))
            || args
                .windows(2)
                .any(|pair| pair[0] == "--property" && pair[1].starts_with("CPUQuota="));
        let masks_runtime = args.windows(2).any(|pair| pair == ["--tmpfs", "/run"]);
        let masks_cgroup = args.windows(2).any(|pair| pair == ["--tmpfs", "/sys"]);
        if !has_scope || !has_cpu_limit || !masks_runtime || !masks_cgroup {
            return None;
        }
        let metadata = std::fs::metadata(&runtime_dir).ok()?;
        let uid = std::fs::metadata("/proc/self").ok()?.uid();
        if !metadata.is_dir() || metadata.uid() != uid || metadata.mode() & 0o077 != 0 {
            return None;
        }
        let sequence = CPU_EVENT_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = runtime_dir.join(format!(
            "tinybox-cpu-event-{}-{sequence}",
            std::process::id()
        ));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .ok()?;
        if std::io::Write::write_all(&mut file, b"nr_throttled 0\n").is_err() {
            let _ = std::fs::remove_file(&path);
            return None;
        }
        env.insert(
            CPU_EVENT_FILE_ENV.into(),
            path.to_string_lossy().into_owned(),
        );
        Some(Self(path))
    }

    fn throttling_observed(&self) -> bool {
        std::fs::read_to_string(&self.0)
            .ok()
            .and_then(|contents| parse_cpu_throttled_counter(&contents))
            .is_some_and(|count| count > 0)
    }
}

#[cfg(target_os = "linux")]
impl Drop for CpuEventReport {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[cfg(target_os = "linux")]
fn parse_cpu_throttled_counter(stats: &str) -> Option<u64> {
    let mut counter = None;
    for line in stats.lines() {
        if let Some(value) = line.strip_prefix("nr_throttled ") {
            if counter.is_some() {
                return None;
            }
            counter = Some(value.parse().ok()?);
        }
    }
    counter
}

#[cfg(target_os = "linux")]
fn prepare_cpu_event_report(
    command: &std::process::Command,
    env: &mut BTreeMap<String, String>,
    observer_attached: bool,
) -> Option<CpuEventReport> {
    observer_attached
        .then(|| CpuEventReport::prepare(command, env))
        .flatten()
}

#[cfg(target_os = "linux")]
fn report_cpu_termination(
    report: Option<&CpuEventReport>,
    observer: Option<&Arc<dyn ExecutionObserver>>,
) {
    if report.is_some_and(CpuEventReport::throttling_observed)
        && let Some(observer) = observer
    {
        observer.termination_cause(tinybox_core::TerminationCause::CpuQuota);
    }
}

fn configure_jail_command(command: &mut std::process::Command, env: &BTreeMap<String, String>) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    command
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    command.env_clear().envs(env);
}

#[cfg(unix)]
struct AsyncPipe(tokio::io::unix::AsyncFd<std::fs::File>);

// The Windows backend also exposes owned captured pipes; retain the portable
// Tokio file adapter for that path.
#[cfg(not(unix))]
type AsyncPipe = tokio::fs::File;

// Keep one fallible call shape across platforms; only Unix pipe registration can fail.
#[cfg_attr(not(unix), allow(clippy::unnecessary_wraps))]
fn async_pipe(file: std::fs::File) -> Result<AsyncPipe> {
    #[cfg(unix)]
    {
        use nix::fcntl::fcntl;

        set_nonblocking_with(&file, |descriptor, argument| fcntl(descriptor, argument))?;
        // The deprecated constructor is retained because Tokio's replacement,
        // `AsyncFd::register`, is unsafe and this workspace forbids unsafe code.
        // `file` is an owned `std::fs::File` moved directly into AsyncFd, so its
        // descriptor stays valid until AsyncFd is dropped.
        #[allow(deprecated)]
        let async_fd = tokio::io::unix::AsyncFd::new(file)
            .map_err(|error| Error::io("register native pipe", &error))?;
        Ok(AsyncPipe(async_fd))
    }
    #[cfg(not(unix))]
    {
        Ok(tokio::fs::File::from_std(file))
    }
}

#[cfg(unix)]
fn set_nonblocking_with<F>(file: &std::fs::File, mut fcntl: F) -> Result<()>
where
    F: FnMut(&std::fs::File, nix::fcntl::FcntlArg<'_>) -> nix::Result<std::os::raw::c_int>,
{
    use nix::fcntl::{FcntlArg, OFlag};

    let flags = fcntl(file, FcntlArg::F_GETFL).map_err(|error| {
        Error::io(
            "make native pipe nonblocking",
            &std::io::Error::from_raw_os_error(error as i32),
        )
    })?;
    fcntl(
        file,
        FcntlArg::F_SETFL(OFlag::from_bits_retain(flags) | OFlag::O_NONBLOCK),
    )
    .map_err(|error| {
        Error::io(
            "make native pipe nonblocking",
            &std::io::Error::from_raw_os_error(error as i32),
        )
    })?;
    Ok(())
}

#[cfg(unix)]
impl AsyncRead for AsyncPipe {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::io::Read;
        loop {
            let mut ready = std::task::ready!(self.0.poll_read_ready(cx))?;
            match ready.try_io(|inner| inner.get_ref().read(buffer.initialize_unfilled())) {
                Ok(Ok(count)) => {
                    buffer.advance(count);
                    return std::task::Poll::Ready(Ok(()));
                }
                Ok(Err(error)) => return std::task::Poll::Ready(Err(error)),
                Err(_would_block) => {}
            }
        }
    }
}

#[cfg(unix)]
impl AsyncWrite for AsyncPipe {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buffer: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        use std::io::Write;
        loop {
            let mut ready = std::task::ready!(self.0.poll_write_ready(cx))?;
            match ready.try_io(|inner| inner.get_ref().write(buffer)) {
                Ok(result) => return std::task::Poll::Ready(result),
                Err(_would_block) => {}
            }
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

type Retained = Arc<tokio::sync::Mutex<Option<OwnedChild>>>;
struct State {
    active: AtomicUsize,
    failed: Mutex<BTreeMap<i32, Retained>>,
    unidentified: Mutex<Vec<Retained>>,
    cleanup: tokio::sync::Mutex<()>,
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

// Standard children do not kill on drop. Keep ownership across supervisor panics
// and aborts so the module can acknowledge cleanup through its normal drain path.
struct RetainedOnDrop {
    child: Option<OwnedChild>,
    group: Option<i32>,
    state: Arc<State>,
}
impl Drop for RetainedOnDrop {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            if let Some(group) = self.group {
                #[cfg(unix)]
                {
                    use nix::{
                        sys::signal::{Signal, killpg},
                        unistd::Pid,
                    };
                    let _ = killpg(Pid::from_raw(group), Signal::SIGKILL);
                }
                let _ = child.terminate();
                self.state
                    .failed
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .insert(group, Arc::new(tokio::sync::Mutex::new(Some(child))));
            } else {
                let _ = child.terminate();
                self.state
                    .unidentified
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(Arc::new(tokio::sync::Mutex::new(Some(child))));
            }
        }
    }
}

/// Local collection whose child is created inside a selected native directory jail.
/// Unavailable backends fail explicitly; this provider never selects an unconfined fallback.
#[derive(Clone)]
pub struct JailLocalHost {
    jail: Jail,
    backend: Arc<dyn JailBackend>,
    limit: usize,
    state: Arc<State>,
}
impl std::fmt::Debug for JailLocalHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JailLocalHost")
            .field("backend", &self.backend.name())
            .finish_non_exhaustive()
    }
}
impl JailLocalHost {
    /// Use the detected backend without weakening unavailable confinement.
    /// # Errors
    /// Rejects unavailable backends without owned-child supervision.
    pub fn new(jail: Jail, limit: usize) -> std::io::Result<Self> {
        Self::with_backend(jail, tinybox_jail::default_owned_backend(), limit)
    }
    /// Use an explicitly selected provider; hosts apply policy to its enforcement facts.
    /// # Errors
    /// Rejects providers that cannot return an owned child.
    pub fn with_backend(
        jail: Jail,
        backend: Arc<dyn JailBackend>,
        limit: usize,
    ) -> std::io::Result<Self> {
        if !backend.is_owned_available() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "native jail supervision is unavailable",
            ));
        }
        let (finished, _) = watch::channel(0);
        Ok(Self {
            jail,
            backend,
            limit,
            state: Arc::new(State {
                active: AtomicUsize::new(0),
                failed: Mutex::new(BTreeMap::new()),
                unidentified: Mutex::new(Vec::new()),
                cleanup: tokio::sync::Mutex::new(()),
                finished,
            }),
        })
    }
    /// Whether a failed cleanup still retains its native child.
    #[must_use]
    pub fn has_pending_cleanup(&self) -> bool {
        !self
            .state
            .failed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_empty()
            || !self
                .state
                .unidentified
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_empty()
    }
    /// Join supervisors and retry all retained native cleanup.
    /// # Errors
    /// Retains failed kill/reap ownership for another cleanup attempt.
    pub async fn drain_checked(&self) -> Result<()> {
        let mut finished = self.state.finished.subscribe();
        while self.state.active.load(Ordering::SeqCst) != 0 {
            if finished.changed().await.is_err() {
                break;
            }
        }
        self.retry_retained_cleanup().await
    }

    async fn retry_retained_cleanup(&self) -> Result<()> {
        let _guard = self.state.cleanup.lock().await;
        let slots: Vec<_> = self
            .state
            .failed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .map(|(id, slot)| (*id, slot.clone()))
            .collect();
        let mut failure = None;
        for (group, slot) in slots {
            let mut child = slot.lock().await;
            if let Some(child) = child.as_mut()
                && let Err(error) = terminate(child, Some(group)).await
            {
                failure.get_or_insert(error);
                continue;
            }
            child.take();
            self.state
                .failed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&group);
        }
        let unidentified = self
            .state
            .unidentified
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        for slot in unidentified {
            let mut child = slot.lock().await;
            if let Some(child) = child.as_mut()
                && let Err(error) = terminate_unidentified_child(child).await
            {
                failure.get_or_insert(error);
                continue;
            }
            child.take();
            self.state
                .unidentified
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .retain(|retained| !Arc::ptr_eq(retained, &slot));
        }
        if let Some(error) = failure {
            Err(error)
        } else {
            Ok(())
        }
    }
}
impl JailLocalHost {
    async fn collect(
        &self,
        request: &ExecRequest,
        observer: Option<Arc<dyn ExecutionObserver>>,
    ) -> Result<ExecOutput> {
        let mut command = crate::LocalHost::command(request)?.into_std();
        // The host explicitly supplies the approved environment for jailed code.
        command.env_clear().envs(&request.env);
        self.collect_command(
            command,
            request.stdin.clone(),
            observer,
            request.env.clone(),
        )
        .await
    }

    /// Collect a prepared shell inside this host's explicit native jail with an
    /// empty environment; [`Self::run_command_observed_with_env`] passes one.
    /// # Errors
    /// Reports unavailable spawn, output bounds and retained kill/reap failures.
    pub async fn run_command_observed(
        &self,
        command: std::process::Command,
        payload: Option<Vec<u8>>,
        observer: Arc<dyn ExecutionObserver>,
    ) -> Result<ExecOutput> {
        self.run_command_observed_with_env(command, payload, observer, BTreeMap::new())
            .await
    }

    /// Collect a prepared command with the exact environment approved by its caller.
    /// # Errors
    /// Reports unavailable spawn, output bounds and retained kill/reap failures.
    pub async fn run_command_observed_with_env(
        &self,
        mut command: std::process::Command,
        payload: Option<Vec<u8>>,
        observer: Arc<dyn ExecutionObserver>,
        env: BTreeMap<String, String>,
    ) -> Result<ExecOutput> {
        command.stdin(if payload.is_some() {
            std::process::Stdio::piped()
        } else {
            std::process::Stdio::null()
        });
        self.collect_command(command, payload, Some(observer), env)
            .await
    }

    async fn collect_command(
        &self,
        mut command: std::process::Command,
        payload: Option<Vec<u8>>,
        observer: Option<Arc<dyn ExecutionObserver>>,
        mut env: BTreeMap<String, String>,
    ) -> Result<ExecOutput> {
        #[cfg(target_os = "linux")]
        let cpu_event_report = prepare_cpu_event_report(&command, &mut env, observer.is_some());
        #[cfg(target_os = "linux")]
        let event_observer = observer.clone();
        configure_jail_command(&mut command, &env);
        let jail = self.jail.clone();
        let backend = self.backend.clone();
        let state = self.state.clone();
        let limit = self.limit;
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|error| failure("supervise native jail", error.to_string()))?;
        let (cancel, mut cancelled) = oneshot::channel::<()>();
        state.active.fetch_add(1, Ordering::SeqCst);
        // The owned supervisor awaits startup even when its caller disappears.
        let task = runtime.spawn(async move {
            let _active = Active(state.clone());
            if !matches!(cancelled.try_recv(), Err(oneshot::error::TryRecvError::Empty)) {
                return Err(failure("start native jail", "execution cancelled".into()));
            }
            let approved_env = env.clone();
            let child = tokio::task::spawn_blocking(move || {
                tinybox_jail::spawn_owned_captured_with_backend_and_env(
                    backend.as_ref(),
                    &jail,
                    command,
                    &approved_env,
                )
            })
            .await
            .map_err(|error| failure("start native jail", error.to_string()))?
            .map_err(|error| Error::io("spawn native jail", &error))?;
            let mut owned = RetainedOnDrop {
                child: Some(child),
                group: None,
                state: state.clone(),
            };
            let group = identify_owned_group(&mut owned).await?;
            owned.group = group;
            let child = owned
                .child
                .as_mut()
                .unwrap_or_else(|| unreachable!("newly retained jail child is present"));
            let pipes = take_captured_pipes(child, payload.is_some());
            let result = match pipes {
                Ok((stdout, stderr, stdin)) => {
                    let budget = Arc::new(AtomicUsize::new(0));
                    let collection = collect_until_exit(
                        stdout,
                        stderr,
                        budget,
                        limit,
                        observer.clone(),
                        async {
                            let ((), status) = tokio::try_join!(
                                async {
                                    if let (Some(mut stdin), Some(payload)) = (stdin, payload) {
                                        stdin
                                            .write_all(&payload)
                                            .await
                                            .map_err(|error| Error::io("write stdin", &error))?;
                                    }
                                    Ok(())
                                },
                                wait_child(child)
                            )?;
                            Ok(status)
                        },
                    );
                    tokio::select! {
                        result = collection => result,
                        () = observer_cancelled(observer.as_deref()) => Err(failure("collect native jail", "execution cancelled".into())),
                        _ = cancelled => Err(failure("collect native jail", "execution cancelled".into())),
                    }
                },
                Err(error) => Err(error),
            };
            let cleanup = terminate(child, group).await;
            let child = owned
                .child
                .take()
                .unwrap_or_else(|| unreachable!("retained jail child is present"));
            retain_cleanup(&state, child, group, cleanup)?;
            result
        });
        let result = task
            .await
            .map_err(|error| failure("collect native jail", error.to_string()));
        drop(cancel);
        // A failed collection (output limit, cancellation) may still have been throttled.
        #[cfg(target_os = "linux")]
        report_cpu_termination(cpu_event_report.as_ref(), event_observer.as_ref());
        result?
    }
}

#[async_trait]
impl Host for JailLocalHost {
    fn name(&self) -> &'static str {
        crate::LOCAL
    }
    fn execution_location(&self) -> tinybox_core::HostExecutionLocation {
        tinybox_core::HostExecutionLocation::Local
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
}
fn retain_cleanup(
    state: &State,
    child: OwnedChild,
    group: Option<i32>,
    outcome: Result<()>,
) -> Result<()> {
    if outcome.is_err() {
        let retained = Arc::new(tokio::sync::Mutex::new(Some(child)));
        if let Some(group) = group {
            state
                .failed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(group, retained);
        } else {
            state
                .unidentified
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(retained);
        }
    }
    outcome
}

fn take_captured_pipes(
    child: &mut OwnedChild,
    payload_requested: bool,
) -> Result<(AsyncPipe, AsyncPipe, Option<AsyncPipe>)> {
    let stdin = match child.take_stdin() {
        Some(stdin) => Some(async_pipe(stdin)?),
        None if payload_requested => {
            return Err(failure(
                "write stdin",
                "owned child did not provide a stdin pipe".into(),
            ));
        }
        None => None,
    };
    Ok((
        async_pipe(pipe(child.take_stdout(), "stdout")?)?,
        async_pipe(pipe(child.take_stderr(), "stderr")?)?,
        stdin,
    ))
}

async fn wait_child(child: &mut OwnedChild) -> Result<Option<i32>> {
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| Error::io("wait native jail", &error))?
        {
            return Ok(status.code());
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}
async fn verified_local_process_group_id(child: &mut OwnedChild) -> Result<Option<i32>> {
    let Some(id) = child.local_process_group_id() else {
        return Ok(None);
    };
    if id == 0 {
        terminate_unidentified_child(child).await?;
        return Err(failure(
            "identify jail child",
            "invalid zero process-group identifier".into(),
        ));
    }
    match i32::try_from(id) {
        Ok(group) => Ok(Some(group)),
        Err(error) => {
            terminate_unidentified_child(child).await?;
            Err(failure("identify jail child", error.to_string()))
        }
    }
}
async fn identify_owned_group(owned: &mut RetainedOnDrop) -> Result<Option<i32>> {
    let child = owned
        .child
        .as_mut()
        .unwrap_or_else(|| unreachable!("newly retained jail child is present"));
    match verified_local_process_group_id(child).await {
        Ok(group) => Ok(group),
        Err(error) => {
            if owned
                .child
                .as_mut()
                .and_then(|child| child.try_wait().ok().flatten())
                .is_some()
            {
                owned.child.take();
            }
            Err(error)
        }
    }
}
async fn terminate_unidentified_child(child: &mut OwnedChild) -> Result<()> {
    terminate_unidentified_child_with_timeout(child, std::time::Duration::from_secs(5)).await
}
async fn terminate_unidentified_child_with_timeout(
    child: &mut OwnedChild,
    deadline: std::time::Duration,
) -> Result<()> {
    let cleanup = async {
        if let Err(error) = child.terminate()
            && child
                .try_wait()
                .map_err(|wait_error| Error::io("inspect unidentified jail child", &wait_error))?
                .is_none()
        {
            return Err(Error::io("terminate unidentified jail child", &error));
        }
        wait_child(child).await.map(|_| ())
    };
    tokio::time::timeout(deadline, cleanup).await.map_err(|_| {
        failure(
            "drain unidentified jail child",
            "cleanup deadline exceeded".into(),
        )
    })?
}
async fn terminate(child: &mut OwnedChild, group: Option<i32>) -> Result<()> {
    #[cfg(unix)]
    {
        if let Some(group) = group {
            use nix::{
                sys::signal::{Signal, killpg},
                unistd::Pid,
            };
            terminate_with_group_ops(
                child,
                group,
                |group| killpg(Pid::from_raw(group), Signal::SIGKILL),
                super::process::group_alive,
            )
            .await
        } else {
            terminate_unidentified_child(child).await
        }
    }
    #[cfg(not(unix))]
    {
        let _ = group;
        terminate_unidentified_child(child).await
    }
}

#[cfg(unix)]
async fn terminate_with_group_ops<K, A, AFut>(
    child: &mut OwnedChild,
    group: i32,
    kill_group: K,
    mut group_alive: A,
) -> Result<()>
where
    K: FnOnce(i32) -> std::result::Result<(), nix::errno::Errno>,
    A: FnMut(i32) -> AFut,
    AFut: std::future::Future<Output = Result<bool>>,
{
    let mut group_error = child
        .try_wait()
        .err()
        .map(|error| Error::io("inspect jail child", &error));
    match group_alive(group).await {
        Ok(true) => {
            if let Err(error) = kill_jail_group(group, kill_group, &mut group_alive).await {
                group_error.get_or_insert(error);
            }
        }
        Ok(false) => {}
        Err(error) => {
            group_error.get_or_insert(error);
        }
    }
    let completion = async {
        if let Err(error) = child.terminate()
            && child
                .try_wait()
                .map_err(|wait_error| Error::io("inspect jail child", &wait_error))?
                .is_none()
        {
            return Err(Error::io("kill jail child", &error));
        }
        wait_child(child).await?;
        while group_alive(group).await? {
            tokio::task::yield_now().await;
        }
        Ok(())
    };
    match tokio::time::timeout(std::time::Duration::from_secs(5), completion).await {
        Ok(result) => result,
        Err(_) => Err(group_error
            .unwrap_or_else(|| failure("drain native jail", "cleanup deadline exceeded".into()))),
    }
}
fn failure(operation: &'static str, message: String) -> Error {
    Error::Backend {
        sandbox: "jail".into(),
        operation,
        message,
    }
}

#[cfg(unix)]
async fn kill_jail_group<F>(
    group: i32,
    kill: impl FnOnce(i32) -> std::result::Result<(), nix::errno::Errno>,
    alive: impl FnOnce(i32) -> F,
) -> Result<()>
where
    F: std::future::Future<Output = Result<bool>>,
{
    match kill(group) {
        // Darwin can deny signalling a group that exited between inspection
        // and SIGKILL. Confirm it has no live members before acknowledging it.
        Err(nix::errno::Errno::EPERM) if !alive(group).await? => Ok(()),
        Ok(()) | Err(nix::errno::Errno::ESRCH) => Ok(()),
        Err(error) => Err(failure("kill jail group", error.to_string())),
    }
}

#[cfg(all(test, unix))]
#[path = "jailed_tests.rs"]
mod tests;

#[cfg(all(test, target_os = "windows"))]
#[path = "jailed_windows_tests.rs"]
mod windows_tests;
