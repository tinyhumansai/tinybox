//! Purely observational sandbox events.
//!
//! A sandbox reports what happened to a workload; it never decides what is
//! allowed. A caller (the host, and through it an audit log) subscribes with an
//! [`EventSink`] and records what it is told.
//!
//! [`SandboxEvent::Denied`] is reserved: no backend emits it today, because
//! none can attribute a denial without privilege (a refused syscall, path or
//! packet fails inside the workload, out of tinybox's sight). A backend that
//! could would report a [`DenialKind`] and an optional target, never a guess.
//! The absence of `Denied` is not the absence of denials. See
//! `docs/specs/contract-2-2.md`.

use std::sync::Mutex;

use serde::{Deserialize, Serialize};

/// Which kind of access the sandbox refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum DenialKind {
    /// A filesystem read, write or execute outside the granted paths.
    Filesystem,
    /// A network connection the policy does not permit.
    Network,
    /// A process or thread creation the sandbox forbids.
    Subprocess,
    /// A system call a filter blocked.
    Syscall,
}

/// Which resource limit a workload reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum LimitKind {
    /// CPU time or share.
    Cpu,
    /// Resident memory.
    Memory,
    /// Process or thread count.
    Pids,
    /// Writable disk.
    Disk,
    /// Wall-clock timeout.
    Timeout,
}

/// One observation about a running workload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SandboxEvent {
    /// The workload started inside the sandbox.
    Started,
    /// The sandbox refused an access. Reserved: no backend emits it yet (see
    /// the module docs).
    Denied {
        /// What was refused.
        kind: DenialKind,
        /// The path, address or syscall refused, when the OS reports it.
        target: Option<String>,
    },
    /// The workload reached a resource limit.
    LimitHit {
        /// The limit reached.
        limit: LimitKind,
    },
    /// The workload ended.
    Exited {
        /// The exit status, or `None` when it was killed by a signal.
        status: Option<i32>,
    },
}

/// Receives events from a sandbox. Implementations must not block.
pub trait EventSink: Send + Sync {
    /// Observe one event for the box `box_id`.
    fn emit(&self, box_id: &str, event: SandboxEvent);
}

/// An [`EventSink`] that keeps every event in memory, for tests and short runs.
#[derive(Debug, Default)]
pub struct CollectingSink {
    events: Mutex<Vec<(String, SandboxEvent)>>,
}

impl CollectingSink {
    /// An empty sink.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Everything received so far, oldest first.
    #[must_use]
    pub fn events(&self) -> Vec<(String, SandboxEvent)> {
        self.events
            .lock()
            .map(|events| events.clone())
            .unwrap_or_default()
    }
}

impl EventSink for CollectingSink {
    fn emit(&self, box_id: &str, event: SandboxEvent) {
        if let Ok(mut events) = self.events.lock() {
            events.push((box_id.to_owned(), event));
        }
    }
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
