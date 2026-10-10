# TinyBox module

The native module owns sandbox providers, box identifiers, detached processes,
and their lifetimes. Clients depend on `tinybox-bus`, whose only production
dependency is serde. It contains serialized vocabulary, no runtime or TinyBus
connection. `tinybox-module::bus` re-exports that vocabulary for compatibility.

## Public surface

The interface is `ai.tinyhumans.tinybox.Box` at
`/ai/tinyhumans/tinybox/Box`. Every argument below is one positional argument;
`Describe` retains its original zero-argument shape and string result.

| Method | Argument | Result |
| --- | --- | --- |
| Describe | none | Original version/backend summary |
| Create | CreateRequest | ResourceInfo |
| Exec | ExecRequest | ExecOutput |
| Inspect | ResourceId | ResourceInfo |
| Close | ResourceId | unit |
| Spawn | SpawnRequest | ProcessRef |
| IsRunning | ProcessRef | bool |
| Cancel | ProcessRef | unit |
| AnalyzeShell | String | ShellAnalysis |

Create requires an explicit backend. This first lifecycle interface constructs
`passthrough`, `docker`, and `namespace` on the local host. An unsupported
backend, including microvm without its required image configuration, fails;
there is no passthrough fallback. Describe remains the existing summary of
compiled providers, rather than claiming every provider is configurable through
Create. Passthrough runs trusted code without isolation.

Clients supply unique, opaque reservation IDs before Create or Spawn. Native
handles remain module-owned. Reservations cannot be reused, even after close or
a failed allocation. If a startup reply is lost, the client still knows which
reservation to close or cancel. Cancel and Close are idempotent and retire even
an unknown reservation: cleanup arriving before delayed startup prevents that
startup from allocating anything. Startup and cleanup share a lock, so cleanup
arriving during allocation runs immediately after allocation finishes.

Cancel leaves an issued process queryable until its resource closes. Close
stops all tracked detached processes, destroys the sandbox, and invalidates
its resource. Reservation tombstones remain until the module instance ends.
Failed cleanup retains ownership so Close can be retried. Callers must close explicitly before unloading the
module. Exec collects output; detached output streaming, file transfer, forwards,
SSH reach, and microVM image configuration need subsequent interfaces.

Operations serialize within each resource; unrelated resources have independent
locks. A detached process can be cancelled after Spawn returns. Close fences new
execution, aborts its resource's collected Exec, waits for its output supervisor
to kill/reap the child, then stops tracked detached processes and destroys the
sandbox. Create, Spawn, Exec, Cancel, and Close run in module-owned tasks, so a
caller dropping or timing out its wait cannot discard startup/cleanup ownership.

IDs are ASCII letters, digits, hyphens, or underscores, at most 128 bytes.
Admission is capped at 64 live resources, 64 retained processes per resource,
and 4096 reservation tombstones per module instance. Failed, cancelled, and
closed reservations keep counting for that instance's whole lifetime; a
process-cached module can exhaust new admission after repeated Create/Spawn
cycles. Reached capacity returns ResourceLimit and never evicts replay history.
Cancelled/completed process entries likewise count toward their resource's 64
slots until Close. A future generation-based reservation protocol is needed
for indefinite reuse without losing stale-retry safety. Issued resources can still
be closed when the admission budget is exhausted. Collected commands use
LimitedLocalHost with a combined 1 MiB stdout/stderr budget enforced during
reading. Overflow fails explicitly and kills/reaps the host child; it is never
silent truncation.

AnalyzeShell removes quoted heredoc bodies before structural scanning. It
returns segments and hidden-execution/redirection facts. Authorization,
credential/path restrictions, and access-tier decisions remain host policy.
Errors use the stable dotted names declared in `tinybox-bus`; backend failures
retain the underlying diagnostic without exposing native handles.

## Native boundary

The SDK owns ABI v1 exports and the module runtime. The artifact remains
`libtinybox.so`, `libtinybox.dylib`, or `tinybox.dll`. The manifest declares all
methods and the test compares that declaration with the dispatch table.
`verify_module` loads the compiled artifact through ModuleHost and exercises
analysis, creation, execution, inspection, and close. In-memory bus tests also
exercise detached cancellation and cleanup. Modules are trusted native code;
the module itself is not confined by the sandboxes it creates.
