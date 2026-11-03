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
For Linux native executions in a scoped cgroup-v2 CPU quota, a positive
`nr_throttled` counter emits `LimitHit { limit: Cpu }` before the exit event.
This indicates that the quota throttled execution; it does not indicate CPU
exhaustion or a process failure.

Signals are observational and best-effort. Their bodies include the caller's
resource and process reservations for correlation. This contract does not
report stdio process events, access denials, or other resource-limit
observations.
