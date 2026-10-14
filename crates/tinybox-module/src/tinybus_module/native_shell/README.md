# Native shell execution

This module prepares caller-approved local shell requests. The retained context
owns the safe environment snapshot, private scratch and a supervised native
collector. It rejects invalid requests before consuming a process reservation.
Resource streams own replay, output budgets, timeout publication and cleanup
barriers. Explicit confinement uses the native jail contract and refuses
unavailable enforcement.

See [the contract](../../../../../docs/specs/native-shell-execution.md) and
[its sequence](../../../../../docs/plans/native-shell-execution.md).

Output release and resource close explicitly remove private scratch on a
blocking worker after draining the native collector. Timeout and cancellation
drain the process but retain scratch for as long as its journal is retained. A deletion failure is returned to the caller and retains the context
and scratch path for a later cleanup retry.

Preparation runs on Tokio’s blocking pool so filesystem and jail preflight I/O
do not stall the module’s async worker.

Stream admission snapshots shell inputs under the resource lock, releases it
before preparation, and rechecks resource ownership after preparation. Close
and Shutdown can finish while preparation is stalled; late completion cannot
publish an execution for a closed resource.

A prepared shell that loses admission is explicitly disposed on the blocking
pool. Failed deletion retains its context in the resource registry; a later
Close (including for an already closed resource) or Shutdown retries cleanup.

Preparation validates the process reservation and claims a bounded pending slot
before scheduling blocking work. Pending preparations and retained journals
share the module admission budget. Close fences the resource and stops owned
work before reporting failed scratch deletion. The sanitized child environment
includes resource variables, with explicit shell-request overrides applied last.
On Unix, nonempty RUSTUP_HOME and CARGO_HOME values are snapshotted as OS values, preserving non-UTF-8 path bytes. Empty values are treated as unset. Explicit resource and shell-request overrides retain their existing precedence. The snapshot carries only these two names as additional host values.
