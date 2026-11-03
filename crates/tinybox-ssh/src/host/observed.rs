//! Remote process-group ownership for live SSH execution.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};

const MEMBERS_REMAIN_FUNCTION: &str = "members_remain() { \
    if ! command -v ps >/dev/null 2>&1 || ! command -v awk >/dev/null 2>&1; then return 0; fi; \
    listing=$(ps -e -o pid= -o pgid= 2>/dev/null) || return 0; \
    state=$(printf '%s\\n' \"$listing\" | awk -v group=\"$group\" 'NF == 0 { next } $1 !~ /^[0-9]+$/ || $2 !~ /^[0-9]+$/ { bad=1; next } $2 == group && $1 != group { found=1 } END { if (bad) print \"unknown\"; else if (found) print \"present\"; else print \"absent\" }') || return 0; \
    case \"$state\" in absent) return 1;; present|unknown|'') return 0;; *) return 0;; esac; \
}";

use async_trait::async_trait;
use tinybox_core::{Error, ExecRequest, ExecutionObserver, OutputStream, Result};
use tokio::sync::Notify;
use uuid::Uuid;

use super::SshTarget;

#[derive(Debug, Clone)]
pub(super) struct RemoteCleanupState(Arc<Mutex<BTreeMap<String, Entry>>>);

#[derive(Debug, Clone)]
struct Entry {
    directory: String,
    pending: bool,
}

impl Default for RemoteCleanupState {
    fn default() -> Self {
        Self(Arc::new(Mutex::new(BTreeMap::new())))
    }
}

impl RemoteCleanupState {
    pub(super) fn reserve(&self) -> (String, String) {
        let id = Uuid::new_v4().simple().to_string();
        let directory = format!("/tmp/.tinybox-observed-{id}");
        self.entries().insert(
            id.clone(),
            Entry {
                directory: directory.clone(),
                pending: false,
            },
        );
        (id, directory)
    }

    pub(super) fn reserve_guard(&self, id: String) -> ReservationGuard {
        ReservationGuard {
            state: self.clone(),
            id,
        }
    }

    pub(super) fn pending(&self) -> Vec<(String, String)> {
        self.entries()
            .iter()
            .filter(|(_, entry)| entry.pending)
            .map(|(id, entry)| (id.clone(), entry.directory.clone()))
            .collect()
    }

    pub(super) fn has_pending(&self) -> bool {
        self.entries().values().any(|entry| entry.pending)
    }

    pub(super) fn mark_pending(&self, id: &str) {
        if let Some(entry) = self.entries().get_mut(id) {
            entry.pending = true;
        }
    }

    pub(super) fn remove(&self, id: &str) {
        self.entries().remove(id);
    }

    pub(super) fn contains(&self, id: &str) -> bool {
        self.entries().contains_key(id)
    }

    fn entries(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, Entry>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Marks an unfinished reservation as pending if observed execution unwinds.
#[derive(Debug)]
pub(super) struct ReservationGuard {
    state: RemoteCleanupState,
    id: String,
}

impl Drop for ReservationGuard {
    fn drop(&mut self) {
        self.state.mark_pending(&self.id);
    }
}

pub(super) fn prepare_request(target: &SshTarget, id: &str, directory: &str) -> ExecRequest {
    let owner_file = format!("{directory}/owner");
    let wrapper = format!(
        "umask 077; dir={dir}; owner={owner}; \
         if ! mkdir \"$dir\" 2>/dev/null; then exit 125; fi; \
         if ! printf '%s\\n' {id} > \"$owner\"; then rm -rf \"$dir\"; exit 125; fi; \
         printf 'ready\\n'",
        dir = tinybox_core::shell::quote(directory),
        owner = tinybox_core::shell::quote(&owner_file),
        id = tinybox_core::shell::quote(id),
    );
    ssh_request(target, &wrapper)
}

pub(super) fn request(
    target: &SshTarget,
    request: &ExecRequest,
    id: &str,
    directory: &str,
) -> Result<ExecRequest> {
    if request.argv.is_empty() {
        return Err(Error::EmptyCommand {
            sandbox: super::NAME.to_owned(),
        });
    }
    let pid_file = format!("{directory}/pid");
    let status_file = format!("{directory}/status");
    let status_tmp_file = format!("{directory}/status.tmp");
    let wrapper_file = format!("{directory}/wrapper");
    let owner_file = format!("{directory}/owner");
    let script = tinybox_core::shell::script(&request.argv, request.cwd.as_deref(), &request.env);
    let child = format!(
        "dir={}; if ! printf '%s\\n' \"$$\" > {}; then exit 125; fi; \
         trap ':' TERM; ( trap - TERM; /bin/sh -c {} <&3 ) & command_pid=$!; \
         wait \"$command_pid\"; code=$?; \
         if ! printf '%s\\n' \"$code\" > {}; then if [ ! -d \"$dir\" ]; then while :; do sleep 3600; done; fi; exit 125; fi; \
         trap '' TERM; if ! mv -f {} {}; then if [ ! -d \"$dir\" ]; then while :; do sleep 3600; done; fi; exit 125; fi; trap ':' TERM; \
         group=$$; {members_remain}; if members_remain; then while :; do sleep 3600; done; fi; : {id}",
        tinybox_core::shell::quote(directory),
        tinybox_core::shell::quote(&pid_file),
        tinybox_core::shell::quote(&script),
        tinybox_core::shell::quote(&status_tmp_file),
        tinybox_core::shell::quote(&status_tmp_file),
        tinybox_core::shell::quote(&status_file),
        members_remain = MEMBERS_REMAIN_FUNCTION,
        id = tinybox_core::shell::quote(id)
    );
    let wrapper = format!(
        "exec 3<&0; dir={dir}; pid_file={pid}; status_file={status}; wrapper_file={wrapper_file}; owner={owner}; \
         if [ ! -d \"$dir\" ] || [ \"$(cat \"$owner\" 2>/dev/null)\" != {id} ]; then exit 125; fi; \
         if ! printf '%s\\n' \"$$\" > \"$wrapper_file\"; then exit 125; fi; \
         if [ ! -d \"$dir\" ] || [ \"$(cat \"$owner\" 2>/dev/null)\" != {id} ]; then exit 125; fi; \
         ( exec setsid /bin/sh -c {child} <&3 ) & launcher=$!; \
         count=0; while [ ! -f \"$pid_file\" ]; do \
           if ! kill -0 \"$launcher\" 2>/dev/null; then wait \"$launcher\"; code=$?; exit \"$code\"; fi; \
           count=$((count + 1)); if [ \"$count\" -ge 1000 ]; then kill -KILL \"$launcher\" 2>/dev/null || true; wait \"$launcher\" 2>/dev/null || true; exit 125; fi; \
           sleep 0.01; \
         done; \
         while [ ! -f \"$status_file\" ]; do \
           if ! kill -0 \"$launcher\" 2>/dev/null; then wait \"$launcher\"; code=$?; break; fi; \
           sleep 0.01; \
         done; \
         if [ -f \"$status_file\" ]; then code=$(cat \"$status_file\" 2>/dev/null); case \"$code\" in ''|*[!0-9]*) exit 125;; esac; fi; \
         group=$(cat \"$pid_file\" 2>/dev/null); case \"$group\" in ''|*[!0-9]*) exit 125;; esac; \
         kill -TERM -\"$group\" 2>/dev/null || true; \
         {members_remain}; \
         count=0; while members_remain; do \
           count=$((count + 1)); if [ \"$count\" -ge 100 ]; then break; fi; sleep 0.01; \
         done; \
         if kill -0 -\"$group\" 2>/dev/null; then kill -KILL -\"$group\" 2>/dev/null || true; fi; \
         wait \"$launcher\" 2>/dev/null || true; \
         count=0; while kill -0 -\"$group\" 2>/dev/null; do \
           count=$((count + 1)); if [ \"$count\" -ge 1000 ]; then exit 124; fi; sleep 0.01; \
         done; \
         printf 'done\\n' > \"$dir/done\" && rm -rf \"$dir\" || exit 125; exit \"$code\"",
        dir = tinybox_core::shell::quote(directory),
        pid = tinybox_core::shell::quote(&pid_file),
        status = tinybox_core::shell::quote(&status_file),
        wrapper_file = tinybox_core::shell::quote(&wrapper_file),
        owner = tinybox_core::shell::quote(&owner_file),
        members_remain = MEMBERS_REMAIN_FUNCTION,
        id = tinybox_core::shell::quote(id),
        child = tinybox_core::shell::quote(&child),
    );
    let mut forwarded = ssh_request(target, &wrapper);
    forwarded.stdin.clone_from(&request.stdin);
    Ok(forwarded)
}

pub(super) fn cleanup_request(
    target: &SshTarget,
    id: &str,
    directory: &str,
    _allow_unstarted: bool,
) -> ExecRequest {
    let (pid_file, owner_file) = (format!("{directory}/pid"), format!("{directory}/owner"));
    let wrapper = format!(
        "dir={dir}; pid_file={pid}; owner={owner}; claim={claim}; \
         wrapper_state() {{ \
           if [ ! -f \"$1/wrapper\" ]; then return 3; fi; \
           wrapper_pid=$(cat \"$1/wrapper\" 2>/dev/null); \
           case \"$wrapper_pid\" in ''|*[!0-9]*) return 2;; esac; \
           listing=$(ps -ww -e -o pid= -o command= 2>/dev/null) || return 2; \
           command=$(printf '%s\\n' \"$listing\" | awk -v wanted=\"$wrapper_pid\" '$1 == wanted {{ $1=\"\"; sub(/^ /, \"\"); print; found=1 }} END {{ if (!found) exit 1 }}') || return 1; \
           case \"$command\" in *{id}*) return 0;; *) return 1;; esac; \
         }}; \
         claim_exists() {{ [ -e \"$claim\" ] || [ -L \"$claim\" ]; }}; \
         group_state() {{ \
           listing=$(ps -e -o pgid= 2>/dev/null) || return 2; \
           printf '%s\\n' \"$listing\" | awk -v wanted=\"$1\" '$1 == wanted {{ found=1 }} END {{ if (found) exit 0; exit 1 }}'; \
         }}; \
         group_leader_owned() {{ \
           listing=$(ps -ww -e -o pid= -o pgid= -o command= 2>/dev/null) || return 2; \
           command=$(printf '%s\\n' \"$listing\" | awk -v wanted=\"$1\" '$1 == wanted && $2 == wanted {{ $1=\"\"; $2=\"\"; sub(/^  */, \"\"); print; found=1 }} END {{ if (!found) exit 1 }}') || return 1; \
           case \"$command\" in *{id}*) return 0;; *) return 1;; esac; \
         }}; \
         restore_original() {{ \
           if [ \"$work\" = \"$claim\" ] && [ ! -e \"$dir\" ]; then mv \"$claim\" \"$dir\" 2>/dev/null || return 1; fi; \
           return 1; \
         }}; \
         stop_owned_group() {{ \
           group_state \"$1\"; state=$?; if [ \"$state\" -eq 1 ]; then return 0; fi; if [ \"$state\" -ne 0 ]; then return 1; fi; \
           group_leader_owned \"$1\" || return 1; \
           kill -TERM -\"$1\" 2>/dev/null || return 1; \
           count=0; while :; do \
             group_state \"$1\"; state=$?; if [ \"$state\" -eq 1 ]; then return 0; fi; if [ \"$state\" -ne 0 ]; then return 1; fi; \
             count=$((count + 1)); if [ \"$count\" -ge 100 ]; then break; fi; sleep 0.01; \
           done; \
           group_leader_owned \"$1\" || return 1; kill -KILL -\"$1\" 2>/dev/null || return 1; \
           count=0; while :; do \
             group_state \"$1\"; state=$?; if [ \"$state\" -eq 1 ]; then return 0; fi; if [ \"$state\" -ne 0 ]; then return 1; fi; \
             count=$((count + 1)); if [ \"$count\" -ge 1000 ]; then return 1; fi; sleep 0.01; \
           done; \
         }}; \
         reclaim_if_inactive() {{ \
           work=\"$dir\"; \
           if claim_exists; then \
             if [ ! -d \"$claim\" ]; then return 1; fi; \
             if [ -d \"$dir\" ]; then return 1; fi; work=\"$claim\"; \
             wrapper_state \"$work\"; wrapper_status=$?; \
             if [ \"$wrapper_status\" -eq 0 ]; then restore_original; return 1; fi; \
             if [ \"$wrapper_status\" -ne 1 ] && [ \"$wrapper_status\" -ne 3 ]; then return 1; fi; \
           elif [ -d \"$dir\" ]; then \
             wrapper_state \"$dir\"; wrapper_status=$?; \
             if [ \"$wrapper_status\" -eq 0 ] || [ \"$wrapper_status\" -eq 2 ]; then return 1; fi; \
             if ! mv \"$dir\" \"$claim\" 2>/dev/null; then return 1; fi; work=\"$claim\"; \
           else printf 'clean\\n'; return 0; fi; \
           if [ ! -f \"$work/owner\" ] || [ \"$(cat \"$work/owner\" 2>/dev/null)\" != {id} ]; then return 1; fi; \
           wrapper_state \"$work\"; wrapper_status=$?; \
           if [ \"$wrapper_status\" -eq 0 ]; then \
             restore_original; return 1; \
           fi; \
           if [ \"$wrapper_status\" -ne 1 ] && [ \"$wrapper_status\" -ne 3 ]; then restore_original; return 1; fi; \
           stale_pid=$(cat \"$work/pid\" 2>/dev/null); \
           if [ -n \"$stale_pid\" ]; then \
             case \"$stale_pid\" in ''|*[!0-9]*) restore_original; return 1;; esac; \
             group_state \"$stale_pid\"; group_status=$?; \
             if [ \"$group_status\" -eq 0 ]; then stop_owned_group \"$stale_pid\" || {{ restore_original; return 1; }}; \
             elif [ \"$group_status\" -ne 1 ]; then restore_original; return 1; fi; \
           fi; \
           rm -rf \"$work\" || return 1; \
           printf 'clean\\n'; return 0; \
         }}; \
         if claim_exists; then reclaim_if_inactive || {{ printf 'pending\\n'; exit 1; }}; exit 0; fi; \
         if [ ! -d \"$dir\" ]; then printf 'clean\\n'; exit 0; fi; \
         if [ ! -f \"$owner\" ] || [ \"$(cat \"$owner\" 2>/dev/null)\" != {id} ]; then printf 'clean\\n'; exit 0; fi; \
         count=0; while [ ! -f \"$pid_file\" ] && [ -d \"$dir\" ]; do \
           count=$((count + 1)); if [ \"$count\" -ge 1000 ]; then reclaim_if_inactive || {{ printf 'pending\\n'; exit 1; }}; exit 0; fi; sleep 0.01; \
         done; \
         if [ ! -f \"$pid_file\" ]; then reclaim_if_inactive || {{ printf 'pending\\n'; exit 1; }}; exit 0; fi; \
         pid=$(cat \"$pid_file\"); case \"$pid\" in ''|*[!0-9]*) printf 'pending\\n'; exit 1;; esac; \
         wrapper_state \"$dir\"; wrapper_status=$?; \
         if [ \"$wrapper_status\" -eq 1 ] || [ \"$wrapper_status\" -eq 3 ]; then reclaim_if_inactive || {{ printf 'pending\\n'; exit 1; }}; exit 0; fi; \
         if [ \"$wrapper_status\" -ne 0 ]; then printf 'pending\\n'; exit 1; fi; \
         group_state \"$pid\"; group_status=$?; \
         if [ \"$group_status\" -eq 1 ]; then reclaim_if_inactive || {{ printf 'pending\\n'; exit 1; }}; exit 0; fi; \
         if [ \"$group_status\" -ne 0 ]; then printf 'pending\\n'; exit 1; fi; \
         group_leader_owned \"$pid\" || {{ printf 'pending\\n'; exit 1; }}; \
         kill -TERM -\"$pid\" 2>/dev/null || true; \
         count=0; while [ -d \"$dir\" ] && [ ! -f \"$dir/done\" ]; do \
           count=$((count + 1)); if [ \"$count\" -ge 100 ]; then break; fi; sleep 0.01; \
         done; \
         if [ -d \"$dir\" ] && [ ! -f \"$dir/done\" ]; then kill -KILL -\"$pid\" 2>/dev/null || true; fi; \
         count=0; while [ -d \"$dir\" ]; do \
           count=$((count + 1)); if [ \"$count\" -ge 100 ]; then reclaim_if_inactive || {{ printf 'pending\\n'; exit 1; }}; exit 0; fi; sleep 0.01; \
         done; printf 'clean\\n'",
        dir = tinybox_core::shell::quote(directory),
        pid = tinybox_core::shell::quote(&pid_file),
        owner = tinybox_core::shell::quote(&owner_file),
        id = tinybox_core::shell::quote(id),
        claim = tinybox_core::shell::quote(&format!("{directory}.cleanup")),
    );
    ssh_request(target, &wrapper)
}

pub(super) fn supports_process_groups(target: &SshTarget) -> ExecRequest {
    ssh_request(target, "command -v setsid >/dev/null 2>&1")
}

fn ssh_request(target: &SshTarget, remote_command: &str) -> ExecRequest {
    let mut argv = vec!["ssh".to_owned()];
    argv.extend(target.connection_flags());
    // Cleanup must settle even when the remote is unreachable; a bounded
    // connection attempt leaves its owner handle available for explicit retry.
    argv.extend(["-o".to_owned(), "ConnectTimeout=10".to_owned()]);
    argv.push(target.destination().to_owned());
    argv.push("--".to_owned());
    argv.push(remote_command.to_owned());
    ExecRequest::new(argv)
}

pub(super) fn cleanup_result(output: &tinybox_core::ExecOutput) -> Result<()> {
    if output.exit_code == 0 && output.stdout == b"clean\n" {
        Ok(())
    } else {
        Err(Error::ObservedCleanupPending {
            provider: super::NAME.to_owned(),
        })
    }
}

pub(super) fn unsupported_process_groups() -> Error {
    Error::UnsupportedStreaming {
        provider: "ssh without remote process-group support".to_owned(),
    }
}

#[derive(Debug)]
pub(super) struct Bridge {
    observer: Arc<dyn ExecutionObserver>,
    inner: Arc<dyn tinybox_core::Host>,
    target: SshTarget,
    state: RemoteCleanupState,
    id: String,
    directory: String,
    failed_output: Mutex<Option<Error>>,
    stop: Notify,
    cleanup_lock: tokio::sync::Mutex<()>,
}

impl Bridge {
    pub(super) fn new(
        observer: Arc<dyn ExecutionObserver>,
        inner: Arc<dyn tinybox_core::Host>,
        target: SshTarget,
        state: RemoteCleanupState,
        id: String,
        directory: String,
    ) -> Arc<Self> {
        Arc::new(Self {
            observer,
            inner,
            target,
            state,
            id,
            directory,
            failed_output: Mutex::new(None),
            stop: Notify::new(),
            cleanup_lock: tokio::sync::Mutex::new(()),
        })
    }

    pub(super) async fn cleanup(&self) -> Result<()> {
        self.cleanup_with(false).await
    }

    pub(super) async fn cleanup_finished(&self) -> Result<()> {
        self.cleanup_with(true).await
    }

    async fn cleanup_with(&self, allow_unstarted: bool) -> Result<()> {
        let _guard = self.cleanup_lock.lock().await;
        if !self.state.contains(&self.id) {
            return Ok(());
        }
        let command = cleanup_request(&self.target, &self.id, &self.directory, allow_unstarted);
        match self.inner.run(&command).await {
            Ok(output) => match cleanup_result(&output) {
                Ok(()) => {
                    self.state.remove(&self.id);
                    Ok(())
                }
                Err(error) => Err(error),
            },
            Err(_) => Err(Error::ObservedCleanupPending {
                provider: super::NAME.to_owned(),
            }),
        }
    }

    pub(super) fn take_output_error(&self) -> Option<Error> {
        self.failed_output
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
    }
}

#[async_trait]
impl ExecutionObserver for Bridge {
    fn output(&self, stream: OutputStream, bytes: &[u8]) -> Result<()> {
        if let Err(error) = self.observer.output(stream, bytes) {
            let mut failure = self
                .failed_output
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if failure.is_none() {
                *failure = Some(error);
                self.stop.notify_one();
            }
        }
        Ok(())
    }

    fn termination_cause(&self, cause: tinybox_core::TerminationCause) {
        self.observer.termination_cause(cause);
    }

    async fn cancelled(&self) {
        let stopped = self.stop.notified();
        tokio::pin!(stopped);
        stopped.as_mut().enable();
        if self
            .failed_output
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_none()
        {
            tokio::select! {
                () = self.observer.cancelled() => {},
                () = stopped => {},
            }
        }
        let _ = self.cleanup().await;
    }
}
