# TinyBox contract 2.2

Contract 2.2 adds one broadcast signal to `ai.tinyhumans.tinybox.Box`:

| Signal | Body |
| --- | --- |
| `ProcessEvent` | `ProcessEvent { process: ProcessRef, event: SandboxEvent }` |

The module emits `Started` after the first successful `StartExec`,
`StartJailedExec`, `StartJailedExecWithResources`, `StartShellExec`, or
`StartNativeShellExec` for a process reservation, then emits
`Exited { status: Some(code) }` after its supervisor observes the terminal
exit status. A replayed start does not duplicate lifecycle events. For
executions terminated by their wall-clock timeout, the module emits
`LimitHit { limit: Timeout }` before `Exited { status: None }`.
For Linux native executions in a scoped cgroup-v2 scope
(`StartJailedExecWithResources`), the scope's own counters, read before it is
stopped, add a `LimitHit` before the exit event:

| Counter | Event | Meaning |
| --- | --- | --- |
| `cpu.stat` `nr_throttled` > 0 | `LimitHit { limit: Cpu }` | The quota throttled execution; not CPU exhaustion or a failure. |
| `memory.events` `oom_kill` > 0 | `LimitHit { limit: Memory }` | The kernel killed a process at the memory limit. |
| `pids.events` `max` > 0 | `LimitHit { limit: Pids }` | A fork was refused at the task limit; the workload may have carried on. |

They come in that order, one each at most. `Disk` has no producer: no backend
enforces a disk budget.

Signals are observational and best-effort. Their bodies include the caller's
resource and process reservations for correlation. This contract does not
report stdio process events.

`Denied` is reserved and never emitted. No backend can attribute an access
denial without privilege: a seccomp-denied call, a Landlock or Seatbelt
refusal, a dropped packet and a missing network all fail inside the workload,
where tinybox does not see them. Observing them would take the kernel audit
log, a seccomp user-notify supervisor, or a packet log, all of which need root
or change what the workload sees. A host must not read the absence of
`Denied` as the absence of denials.
