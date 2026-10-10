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
its resource. Reservation tombstones remain until the module instance ends. Failed cleanup retains ownership
so Close can be retried. Callers must close explicitly before unloading the
module. Exec collects output; detached output streaming, file transfer, forwards,
SSH reach, and microVM image configuration need subsequent interfaces.

Resource operations currently serialize within a module instance, including
Exec. A detached process can be cancelled after Spawn returns; a collected Exec
is not cancellable by this interface. Long-lived workloads should use Spawn. Create, Spawn, and Exec run in
module-owned tasks: dropping or timing out the caller's wait does not abort
native startup or discard its ownership. Close waits for collected Exec to
finish before destroying the resource, preventing a cleanup/execution race.

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
