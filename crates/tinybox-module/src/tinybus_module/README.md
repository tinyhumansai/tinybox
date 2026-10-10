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
| Reserve | ReserveRequest | ResourceId |
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

Clients call Reserve with Resource or Process(resource) before Create or Spawn.
The module mints an opaque, single-use handle without starting native work.
Unused reservations expire after 60 seconds and are bounded at 4096; Reserve
reclaims expired entries. Consuming, closing, or cancelling a reservation removes
it. Create and Spawn accept only still-live reservations, so forgotten or old
handles can never resurrect side effects. Reservations are independent: startup
can arrive out of order and cleanup removes only its selected target. Process
reservations are bound to their resource. Random per-instance identity and a
monotonic sequence prevent IDs from being reused across module incarnations.

Native handles remain module-owned. Close/Cancel before startup removes the
reservation, and cleanup during native startup waits for its resource lock and
cleans the eventual result. Completed/cancelled process entries are removed
rather than consuming admission forever. IsRunning reports false for a process
that is no longer retained. Native cleanup errors retain ownership for retry.
Callers must close explicitly before unloading the module. Output streaming,
transfer, forwarding, SSH and microVM configuration remain subsequent slices.

Operations serialize within each resource; unrelated resources have independent
locks. A detached process can be cancelled after Spawn returns. Close fences new
execution, aborts its resource's collected Exec, waits for its output supervisor
to kill/reap the child, then stops tracked detached processes and destroys the
sandbox. Create, Spawn, Exec, Cancel, and Close run in module-owned tasks, so a
caller dropping or timing out its wait cannot discard startup/cleanup ownership.

Admission bounds live resources at 64, live processes at 64 per resource, and
queued process startups at 64 per resource. Unused reservation capacity is
reclaimed on consumption, cleanup or expiry. Sequential Create/Close and
Spawn/Cancel cycles impose no lifetime admission limit and keep no history sets.
Collected commands use LimitedLocalHost with a combined 1 MiB stdout/stderr
budget enforced during reading; overflow fails rather than truncating output.

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
