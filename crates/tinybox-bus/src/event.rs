//! Wire vocabulary for network allowlists and sandbox observations.
//!
//! These mirror the model types in `tinybox-core` so a module and a host can
//! exchange them without sharing a dependency. They carry no policy: a sandbox
//! reports what happened and the caller decides what to do about it.

use serde::{Deserialize, Serialize};

/// One process-scoped sandbox observation sent by the `TinyBox` module.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessEvent {
    /// Resource and process identifiers chosen by the caller.
    pub process: crate::ProcessRef,
    /// What the sandbox observed about this process.
    pub event: SandboxEvent,
}

/// Hosts and ports an allowlisted box may reach.
///
/// Hostnames are resolved outside the box and pinned; metadata endpoints are
/// always refused. See `tinybox_core::EgressAllowlist` for the full rules.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct EgressAllowlist {
    /// Host names or IP literals.
    pub hosts: Vec<String>,
    /// TCP ports.
    pub ports: Vec<u16>,
}

/// Which kind of access a sandbox refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DenialKind {
    /// Filesystem access outside the granted paths.
    Filesystem,
    /// A network connection the policy forbids.
    Network,
    /// Process creation the sandbox forbids.
    Subprocess,
    /// A system call a filter blocked.
    Syscall,
}

/// Which resource limit a workload reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
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
#[serde(tag = "event", rename_all = "snake_case")]
pub enum SandboxEvent {
    /// The workload started.
    Started,
    /// The sandbox refused an access.
    Denied {
        /// What was refused.
        kind: DenialKind,
        /// The path, address or syscall, when the OS reports it.
        #[serde(default)]
        target: Option<String>,
    },
    /// The workload reached a resource limit.
    LimitHit {
        /// The limit reached.
        limit: LimitKind,
    },
    /// The workload ended.
    Exited {
        /// Exit status, or `None` when killed by a signal.
        #[serde(default)]
        status: Option<i32>,
    },
}

#[cfg(test)]
#[path = "event_tests.rs"]
mod tests;
