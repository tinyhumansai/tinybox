//! Native process-group ownership and joined detached cleanup.

use super::{Active, LimitedLocalHost};
use crate::LocalHost;
use std::sync::atomic::Ordering;
use tinybox_core::{Error, ExecRequest, Result};
use tokio::io::AsyncWriteExt;
use tokio::process::{Child, Command};
use tokio::sync::oneshot;

/// An owned native process group. Drop requests cancellation; stop acknowledges cleanup.
#[derive(Debug)]
pub struct ManagedProcess {
    cancel: Option<oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<Result<()>>>,
    terminal: std::result::Result<(), String>,
    cleanup_failed: std::sync::Arc<std::sync::atomic::AtomicBool>,
    state: std::sync::Arc<super::State>,
    group: i32,
    supervisor_failed: bool,
}

impl ManagedProcess {
    /// Whether the supervisor still owns running native work.
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.cleanup_failed.load(Ordering::SeqCst)
            || self.task.as_ref().is_some_and(|task| !task.is_finished())
    }

    /// Kill the process group and wait for the supervisor to reap its direct child.
    ///
    /// # Errors
    /// Reports command failures once after successful cleanup, and retains native
    /// signalling/reaping failures for cleanup retry.
    pub async fn stop(&mut self) -> Result<()> {
        self.cancel.take();
        if let Some(task) = self.task.as_mut() {
            self.terminal = match task.await {
                Ok(result) => result.map_err(|error| error.to_string()),
                Err(error) => {
                    self.cleanup_failed.store(true, Ordering::SeqCst);
                    self.supervisor_failed = true;
                    Err(error.to_string())
                }
            };
            self.task = None;
        } else if self.cleanup_failed.load(Ordering::SeqCst) && !self.supervisor_failed {
            self.terminal = super::retry_cleanup(&self.state, self.group)
                .await
                .map_err(|error| error.to_string());
            self.cleanup_failed
                .store(self.terminal.is_err(), Ordering::SeqCst);
        }
        let result = self.terminal.clone().map_err(|message| Error::Backend {
            sandbox: crate::LOCAL.into(),
            operation: "stop supervised process",
            message,
        });
        if self.is_cleaned() {
            self.terminal = Ok(());
        }
        result
    }

    /// Whether native cleanup has been acknowledged, independent of command outcome.
    #[must_use]
    pub fn is_cleaned(&self) -> bool {
        self.task.is_none() && !self.cleanup_failed.load(Ordering::SeqCst)
    }
}

impl Drop for ManagedProcess {
    fn drop(&mut self) {
        self.cancel.take();
    }
}

impl LimitedLocalHost {
    /// Start an owned local process group with output discarded.
    ///
    /// # Errors
    /// Rejects unsupported platforms, empty commands and native startup failures.
    pub fn spawn(&self, request: &ExecRequest) -> Result<ManagedProcess> {
        let mut command = LocalHost::command(request)?;
        prepare(&mut command)?;
        command
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        let mut child = command
            .spawn()
            .map_err(|error| Error::io("spawn", &error))?;
        let group = group(&child)?;
        let stdin = child.stdin.take();
        let payload = request.stdin.clone();
        let (cancel, cancelled) = oneshot::channel::<()>();
        let state = self.state.clone();
        state.active.fetch_add(1, Ordering::SeqCst);
        let cleanup_failed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let failed = cleanup_failed.clone();
        let supervisor_state = state.clone();
        let task = tokio::spawn(async move {
            let _active = Active(supervisor_state.clone());
            let completion = async {
                tokio::try_join!(
                    async {
                        if let (Some(mut stdin), Some(payload)) = (stdin, payload) {
                            stdin
                                .write_all(&payload)
                                .await
                                .map_err(|error| Error::io("write stdin", &error))?;
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
                result = completion => result.map(|_| ()),
                _ = cancelled => Ok(()),
            };
            let cleanup = super::cleanup(&supervisor_state, child, group).await;
            failed.store(cleanup.is_err(), Ordering::SeqCst);
            cleanup?;
            result
        });
        Ok(ManagedProcess {
            cancel: Some(cancel),
            task: Some(task),
            terminal: Ok(()),
            cleanup_failed,
            state,
            group,
            supervisor_failed: false,
        })
    }
}

pub(super) fn prepare(command: &mut Command) -> Result<()> {
    if !cfg!(unix) {
        return Err(Error::Unsupported {
            sandbox: crate::LOCAL.into(),
            capability: tinybox_core::Capability::Detach,
        });
    }
    #[cfg(unix)]
    command.process_group(0);
    #[cfg(not(unix))]
    let _ = command;
    Ok(())
}

pub(super) fn group(child: &Child) -> Result<i32> {
    child
        .id()
        .and_then(|id| i32::try_from(id).ok())
        .ok_or_else(|| Error::Backend {
            sandbox: crate::LOCAL.into(),
            operation: "own process group",
            message: "missing native process identifier".into(),
        })
}

pub(super) async fn terminate(child: &mut Child, group: i32) -> Result<()> {
    cleanup_deadline(
        std::time::Duration::from_secs(5),
        terminate_native(child, group),
    )
    .await
}

async fn cleanup_deadline(
    deadline: std::time::Duration,
    work: impl std::future::Future<Output = Result<()>>,
) -> Result<()> {
    tokio::time::timeout(deadline, work)
        .await
        .map_err(|_| Error::Backend {
            sandbox: crate::LOCAL.into(),
            operation: "await native cleanup",
            message: "cleanup deadline exceeded".into(),
        })?
}

async fn terminate_native(child: &mut Child, group: i32) -> Result<()> {
    #[cfg(unix)]
    {
        use nix::{
            errno::Errno,
            sys::signal::{Signal, killpg},
            unistd::Pid,
        };
        match killpg(Pid::from_raw(group), Signal::SIGKILL) {
            Ok(()) | Err(Errno::ESRCH) => {}
            Err(error) => {
                return Err(Error::Backend {
                    sandbox: crate::LOCAL.into(),
                    operation: "kill process group",
                    message: error.to_string(),
                });
            }
        }
    }
    #[cfg(not(unix))]
    let _ = group;
    child
        .kill()
        .await
        .map_err(|error| Error::io("kill and reap", &error))?;
    wait_group(group, std::time::Duration::from_secs(5), group_alive).await
}

async fn wait_group(
    group: i32,
    deadline: std::time::Duration,
    mut alive: impl FnMut(i32) -> Result<bool>,
) -> Result<()> {
    tokio::time::timeout(deadline, async {
        while alive(group)? {
            tokio::task::yield_now().await;
        }
        Ok(())
    })
    .await
    .map_err(|_| Error::Backend {
        sandbox: crate::LOCAL.into(),
        operation: "await process group termination",
        message: "cleanup deadline exceeded".into(),
    })?
}

#[cfg(target_os = "linux")]
fn group_alive(group: i32) -> Result<bool> {
    for entry in
        std::fs::read_dir("/proc").map_err(|error| Error::io("read process table", &error))?
    {
        let entry = entry.map_err(|error| Error::io("read process entry", &error))?;
        if entry.file_name().to_string_lossy().parse::<u32>().is_err() {
            continue;
        }
        let Ok(stat) = std::fs::read_to_string(entry.path().join("stat")) else {
            continue;
        };
        let Some((_, fields)) = stat.rsplit_once(')') else {
            continue;
        };
        let fields: Vec<_> = fields.split_whitespace().take(3).collect();
        if fields.len() == 3
            && fields[2].parse::<i32>().ok() == Some(group)
            && fields[0] != "Z"
            && fields[0] != "X"
        {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(all(unix, not(target_os = "linux")))]
fn group_alive(group: i32) -> Result<bool> {
    use nix::{errno::Errno, sys::signal::killpg, unistd::Pid};
    match killpg(Pid::from_raw(group), None) {
        Ok(()) => Ok(true),
        Err(Errno::ESRCH) => Ok(false),
        Err(error) => Err(Error::Backend {
            sandbox: crate::LOCAL.into(),
            operation: "observe process group",
            message: error.to_string(),
        }),
    }
}

#[cfg(not(unix))]
fn group_alive(_: i32) -> Result<bool> {
    Ok(false)
}

#[cfg(test)]
#[path = "process_tests.rs"]
mod tests;
