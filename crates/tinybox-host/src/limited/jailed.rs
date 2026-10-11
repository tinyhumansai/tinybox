//! Bounded collection of standard-library children created by native jail backends.
use super::{observer_cancelled, pipe, read_with_observer};
use async_trait::async_trait;
use std::collections::BTreeMap;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use tinybox_core::{Error, ExecOutput, ExecRequest, ExecutionObserver, Host, OutputStream, Result};
use tinybox_jail::{Jail, JailBackend};
use tokio::io::AsyncWriteExt;
use tokio::sync::{oneshot, watch};

type Retained = Arc<tokio::sync::Mutex<Option<std::process::Child>>>;
struct State {
    active: AtomicUsize,
    failed: Mutex<BTreeMap<i32, Retained>>,
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
    child: Option<std::process::Child>,
    group: i32,
    state: Arc<State>,
}
impl Drop for RetainedOnDrop {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            #[cfg(unix)]
            {
                use nix::{
                    sys::signal::{Signal, killpg},
                    unistd::Pid,
                };
                let _ = killpg(Pid::from_raw(self.group), Signal::SIGKILL);
            }
            let _ = child.kill();
            self.state
                .failed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(self.group, Arc::new(tokio::sync::Mutex::new(Some(child))));
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
    /// Rejects unavailable backends and platforms without supervised standard children.
    pub fn new(jail: Jail, limit: usize) -> std::io::Result<Self> {
        Self::with_backend(jail, tinybox_jail::default_backend(), limit)
    }
    /// Use an explicitly selected provider; hosts apply policy to its enforcement facts.
    /// # Errors
    /// Rejects unavailable providers and unsupported native ownership platforms.
    pub fn with_backend(
        jail: Jail,
        backend: Arc<dyn JailBackend>,
        limit: usize,
    ) -> std::io::Result<Self> {
        if !cfg!(unix) || !backend.is_available() {
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
                && let Err(error) = terminate(child, group).await
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
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        command
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let jail = self.jail.clone();
        let backend = self.backend.clone();
        let payload = request.stdin.clone();
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
            let child = tokio::task::spawn_blocking(move || {
                tinybox_jail::spawn_captured_with(backend.as_ref(), &jail, command)
            })
            .await
            .map_err(|error| failure("start native jail", error.to_string()))?
            .map_err(|error| Error::io("spawn native jail", &error))?;
            let group = i32::try_from(child.id())
                .map_err(|error| failure("identify jail child", error.to_string()))?;
            let mut owned = RetainedOnDrop {
                child: Some(child),
                group,
                state: state.clone(),
            };
            let child = owned.child.as_mut().ok_or_else(|| {
                failure("own jail child", "missing native child".into())
            })?;
            let pipes = (|| {
                Ok::<_, Error>((
                    tokio::process::ChildStdout::from_std(pipe(child.stdout.take(), "stdout")?)
                        .map_err(|error| Error::io("attach stdout", &error))?,
                    tokio::process::ChildStderr::from_std(pipe(child.stderr.take(), "stderr")?)
                        .map_err(|error| Error::io("attach stderr", &error))?,
                    child
                        .stdin
                        .take()
                        .map(tokio::process::ChildStdin::from_std)
                        .transpose()
                        .map_err(|error| Error::io("attach stdin", &error))?,
                ))
            })();
            let result = match pipes {
                Ok((stdout, stderr, stdin)) => {
                    let budget = Arc::new(AtomicUsize::new(0));
                    let collection = async {
                        tokio::try_join!(
                            read_with_observer(stdout, budget.clone(), limit, OutputStream::Stdout, observer.clone()),
                            read_with_observer(stderr, budget, limit, OutputStream::Stderr, observer.clone()),
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
                        )
                    };
                    tokio::select! {
                        result = collection => result.map(|(stdout, stderr, (), status)| ExecOutput::new(status.code().unwrap_or(128), stdout, stderr)),
                        () = observer_cancelled(observer.as_deref()) => Err(failure("collect native jail", "execution cancelled".into())),
                        _ = cancelled => Err(failure("collect native jail", "execution cancelled".into())),
                    }
                },
                Err(error) => Err(error),
            };
            let cleanup = terminate(child, group).await;
            let child = owned.child.take().ok_or_else(|| {
                failure("release jail child", "missing native child".into())
            })?;
            retain_cleanup(&state, child, group, cleanup)?;
            result
        });
        let result = task
            .await
            .map_err(|error| failure("collect native jail", error.to_string()));
        drop(cancel);
        result?
    }
}

#[async_trait]
impl Host for JailLocalHost {
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
}
fn retain_cleanup(
    state: &State,
    child: std::process::Child,
    group: i32,
    outcome: Result<()>,
) -> Result<()> {
    if outcome.is_err() {
        state
            .failed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(group, Arc::new(tokio::sync::Mutex::new(Some(child))));
    }
    outcome
}

async fn wait_child(child: &mut std::process::Child) -> Result<std::process::ExitStatus> {
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| Error::io("wait native jail", &error))?
        {
            return Ok(status);
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}
async fn terminate(child: &mut std::process::Child, group: i32) -> Result<()> {
    #[cfg(not(unix))]
    let _ = group;
    #[cfg(unix)]
    {
        use nix::{
            errno::Errno,
            sys::signal::{Signal, killpg},
            unistd::Pid,
        };
        if child
            .try_wait()
            .map_err(|error| Error::io("inspect jail child", &error))?
            .is_none()
            || super::process::group_alive(group)?
        {
            match killpg(Pid::from_raw(group), Signal::SIGKILL) {
                Ok(()) | Err(Errno::ESRCH) => {}
                Err(error) => return Err(failure("kill jail group", error.to_string())),
            }
        }
    }
    let completion = async {
        child
            .kill()
            .map_err(|error| Error::io("kill jail child", &error))?;
        wait_child(child).await?;
        #[cfg(unix)]
        while super::process::group_alive(group)? {
            tokio::task::yield_now().await;
        }
        Ok(())
    };
    tokio::time::timeout(std::time::Duration::from_secs(5), completion)
        .await
        .map_err(|_| failure("drain native jail", "cleanup deadline exceeded".into()))?
}
fn failure(operation: &'static str, message: String) -> Error {
    Error::Backend {
        sandbox: "jail".into(),
        operation,
        message,
    }
}

#[cfg(all(test, unix))]
#[path = "jailed_tests.rs"]
mod tests;
