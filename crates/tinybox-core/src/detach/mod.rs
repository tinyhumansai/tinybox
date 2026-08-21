//! Leaving a process running in a box, and finding it again later.
//!
//! [`Sandbox::exec`](crate::runtime::Sandbox::exec) runs a command to
//! completion and collects its output. That is the right shape for the work
//! tinybox was built for — a build, a test run, an agent's command — and the
//! wrong shape for a server. Starting one through `exec` never returns.
//!
//! # Why this is one mechanism rather than one per backend
//!
//! Docker has `docker exec --detach`, and a local host could hold a
//! [`std::process::Child`]. Neither generalizes: `--detach` hands back nothing
//! a caller could name, and a child handle dies with the process holding it,
//! which is exactly the process a detached command is supposed to outlive. SSH
//! has neither.
//!
//! What every box tinybox can host a server in *does* have is a POSIX shell.
//! So the mechanism is the shell's own: background the command, record its pid
//! in a file named after a [`ProcessId`] tinybox minted, and answer later
//! questions by reading that file. One implementation, identical semantics
//! everywhere, and the backend contributes only its existing
//! [`exec`](crate::runtime::Sandbox::exec) path.
//!
//! # What a backend is promising
//!
//! A sandbox that declares [`Capability::Detach`](crate::Capability::Detach)
//! promises two things beyond running the command: that a write to
//! [`PID_DIR`] survives until the next command, and that the process itself
//! keeps running between commands. A sandbox where either is false — one whose
//! boxes are re-bound per command, or that returns only what the command
//! printed — must decline. A background process that cannot be found or
//! stopped is worse than a refusal, because it looks like it worked.
//!
//! ```
//! use tinybox_core::detach;
//! use tinybox_core::runtime::ExecRequest;
//!
//! let process = detach::mint();
//! let start = detach::start(&process, &ExecRequest::new(["sleep", "60"]))?;
//!
//! // A shell command, because that is what backgrounding requires.
//! assert_eq!(start.program(), Some("/bin/sh"));
//! # Ok::<(), tinybox_core::Error>(())
//! ```

use std::sync::atomic::{AtomicU64, Ordering};

use crate::error::{Error, Result};
use crate::identity::ProcessId;
use crate::runtime::ExecRequest;
use crate::shell;

/// Where pid files are written inside a box.
///
/// `/tmp` rather than the workspace: the workspace is the user's, may be a
/// read-only mount, and is often synced back out. Runtime bookkeeping does not
/// belong in it.
pub const PID_DIR: &str = "/tmp";

/// The shell every detached command is started through.
///
/// Spelled absolutely so a box with an unusual `PATH` still resolves it, and
/// `sh` rather than `bash` because a minimal image often has only the former.
const SHELL: &str = "/bin/sh";

/// Distinguishes ids minted within one process.
static COUNTER: AtomicU64 = AtomicU64::new(0);

/// Mint an identifier for a process about to be started.
///
/// The value is opaque; callers should store it rather than parse it. It is
/// infallible because the text is built here from a fixed prefix and decimal
/// digits, which is always a valid identifier — a `Result` would hand callers
/// an error arm that can never happen.
#[must_use]
pub fn mint() -> ProcessId {
    let ordinal = COUNTER.fetch_add(1, Ordering::Relaxed);
    // Two sources so that two hosts, or two runs, do not collide on a shared
    // box: a monotonic ordinal within this process, and the process's own pid.
    ProcessId::from_generated(format!("p{}-{ordinal}", std::process::id()))
}

/// The path of the file recording `process`'s real pid inside its box.
#[must_use]
pub fn pid_file(process: &ProcessId) -> String {
    format!("{PID_DIR}/tinybox-{process}.pid")
}

/// The command that starts `request` in the background and records its pid.
///
/// The shell writes the pid *before* the outer shell exits, so a caller that
/// gets a successful [`ExecOutput`](crate::runtime::ExecOutput) back can
/// immediately ask whether the process is running and get a truthful answer.
/// Output is discarded: nothing is reading it, and a full pipe would eventually
/// block the very process this is trying to leave running.
///
/// # Errors
///
/// Returns [`Error::EmptyCommand`] when the request names no program. The
/// sandbox is named `detach` because the failure is in this construction, not
/// in any backend.
pub fn start(process: &ProcessId, request: &ExecRequest) -> Result<ExecRequest> {
    if request.argv.is_empty() {
        return Err(Error::EmptyCommand {
            sandbox: "detach".to_owned(),
        });
    }

    let inner = shell::script(&request.argv, request.cwd.as_deref(), &request.env);
    let pid_file = shell::quote(&pid_file(process));
    // `$!` is the pid of the most recent background command, so it is captured
    // before anything else can overwrite it.
    let line = format!("{{ {inner} ; }} </dev/null >/dev/null 2>&1 & echo $! > {pid_file}");

    let mut started = ExecRequest::new([SHELL, "-c", &line]);
    // stdin belongs to the backgrounded command, which is already given
    // /dev/null above; passing the caller's payload here would feed the
    // wrapper instead.
    started.stdin = None;
    Ok(started)
}

/// The command that reports whether `process` is still running.
///
/// Prints `running` or `gone`, and exits zero either way: "the process has
/// finished" is an answer, not a failure, and conflating it with one would make
/// an unreachable box indistinguishable from a completed server.
///
/// Signal `0` performs the kernel's permission and existence check without
/// delivering anything, which is the standard way to ask.
#[must_use]
pub fn probe(process: &ProcessId) -> ExecRequest {
    let pid_file = shell::quote(&pid_file(process));
    let line = format!(
        "if [ -f {pid_file} ] && kill -0 \"$(cat {pid_file})\" 2>/dev/null; \
         then echo running; else echo gone; fi"
    );
    ExecRequest::new([SHELL, "-c", &line])
}

/// What [`probe`] prints when the process is still running.
pub const RUNNING: &str = "running";

/// The command that stops `process` and removes its pid file.
///
/// `TERM` first so the process can shut down on its own terms, then `KILL`
/// after a grace period for one that will not. The pid file is removed either
/// way: leaving it behind would make a later [`probe`] answer about whatever
/// process inherits that pid next, which on a long-lived box is a real
/// possibility and a confusing bug.
///
/// Exits zero when the process was already gone, because stopping something
/// that has already stopped is the outcome the caller wanted.
#[must_use]
pub fn stop(process: &ProcessId, grace: std::time::Duration) -> ExecRequest {
    let pid_file = shell::quote(&pid_file(process));
    let seconds = grace.as_secs().max(1);
    let line = format!(
        "if [ -f {pid_file} ]; then pid=$(cat {pid_file}); \
         kill -TERM \"$pid\" 2>/dev/null; \
         for _ in $(seq {seconds}); do kill -0 \"$pid\" 2>/dev/null || break; sleep 1; done; \
         kill -KILL \"$pid\" 2>/dev/null; rm -f {pid_file}; fi; exit 0"
    );
    ExecRequest::new([SHELL, "-c", &line])
}

/// How long [`stop`] waits for a graceful exit before killing.
pub const DEFAULT_GRACE: std::time::Duration = std::time::Duration::from_secs(5);

#[cfg(test)]
mod test;
