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
| Shutdown | none | unit |
| Capabilities | none | ModuleCapabilities |
| JailStatus | none | JailStatus |
| Reserve | ReserveRequest | ResourceId |
| Create | CreateRequest | ResourceInfo |
| Forward | ForwardRequest | ForwardInfo |
| CloseForward | CloseForwardRequest | unit |
| Exec | ExecRequest | ExecOutput |
| Inspect | ResourceId | ResourceInfo |
| Close | ResourceId | unit |
| Spawn | SpawnRequest | ProcessRef |
| IsRunning | ProcessRef | bool |
| Cancel | ProcessRef | unit |
| AnalyzeShell | String | ShellAnalysis |
| AnalyzeCommand | String | CommandAnalysis |
| BeginFileRead | BeginFileReadRequest | FileReadInfo |
| ReadFileChunk | ReadFileChunkRequest | FileChunk |
| FinishFileRead | FinishFileReadRequest | unit |
| BeginFileWrite | BeginFileWriteRequest | FileWriteInfo |
| WriteFileChunk | WriteFileChunkRequest | FileWriteProgress |
| FinishFileWrite | FinishFileWriteRequest | FileWriteProgress |
| AbortFileWrite | AbortFileWriteRequest | unit |

Capabilities advertises contract version 1.5; 1.0 denotes the original
discovery-only surface. Hosts require equal majors and a module minor at least
as new as their vocabulary, using `tinybox_bus::is_compatible`. Version 1.1
added reserved resource/process ownership and terminal shutdown; 1.2 adds host
selection, sandbox networking/resource/port inputs, effective published-port
facts, and module-owned forwarding. Version 1.3 adds `JailStatus`, which reports
the detected native directory-jail backend's availability, process isolation,
and filesystem, network, and subprocess enforcement. The module probes the
backend; the host applies its own policy to the returned facts. This version is independent of
package/artifact releases. Version 1.4 adds `AnalyzeCommand`, returning generic
classification, executor/environment signals, expansion, background execution,
and literal tokens. Hosts continue to own path resolution, allowlists, approval
gates, and policy-disabled behavior. `AnalyzeShell` retains its arity and result.
Describe remains unchanged.

Version 1.5 adds bounded file transfer for mounted directory workspaces.
Reserve `FileRead(resource)` or `FileWrite(resource)` before opening a transfer.
Paths are relative to the workspace and reject traversal; each resource holds
at most eight active handles, each chunk is at most 64 KiB, and writes are
limited to 256 MiB. Writes remain in a sibling staging file until Finish
atomically publishes them; Abort and resource Close discard unfinished writes.
Exact retries of the most recently acknowledged write chunk and completed
Finish calls replay their acknowledgement. The module implements path
confinement with capability-based local directory handles. Docker workspaces
use their caller-mounted local directory. Image-backed workspaces and SSH
hosts return a stable unsupported error; file transfer does not shell out or
copy data through an execution command. The caller remains responsible for
approving the workspace and requested relative path.

Create requires an explicit backend and rejects one unavailable on the current
platform before it creates a resource slot. `passthrough` is record-only on
platforms where TinyBox cannot supervise native children; Docker is available
on Unix and Windows, and the Linux namespace backend is available only on Linux. An
unsupported backend, including microvm without its required image
configuration, fails; there is no passthrough fallback. Describe remains the
existing summary of compiled providers, rather than claiming every provider is
configurable through Create. Passthrough runs trusted code without isolation.

Create defaults to `HostConfig::Local`. `HostConfig::Ssh` reaches the selected
host through the installed OpenSSH client and its configuration, with optional
port, identity file, known-hosts file, and opt-in `accept-new` host-key policy.
Host selection does not add confinement: pair a remote host with an actual
sandbox when running untrusted code. The requested network policy, resource
limits, and guest port mappings are copied into the sandbox specification; a
backend remains responsible for enforcing the capabilities it advertises.
Docker reports effective published ports in ResourceInfo, including its
selected host port for dynamic mappings. Other backends report no effective
ports unless they implement that fact.

To forward a published guest port, reserve `Forward(resource)` and call
`Forward` with that handle and guest port. The returned opaque `ForwardInfo`
contains the reachable local address. The module holds the tunnel until
`CloseForward`, resource `Close`, or `Shutdown`; repeating the same `Forward` with the
same reservation and guest port replays the same address, while binding that
handle to a different guest port fails. Forward reservations are bounded and
expire like other unused reservations. `Forward` refuses ports the sandbox did
not actually publish, and remote SSH forwards use the existing host's SSH
subprocess lifecycle and host-key policy.

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
that is no longer retained. Command failures are reported once, separately from native cleanup: successfully
reaped process/resource slots are released even when the command failed. Native
cleanup errors retain the child and group for a public Cancel/Close/Shutdown retry.
Callers must call terminal Shutdown before ABI unload or runtime shutdown.
Shutdown is a lifecycle control for the trusted module host. TinyBus currently
does not enforce per-peer method authorization, so the host must keep this
interface on a bus shared only with trusted, admitted peers and authorize its
lifecycle call.
Shutdown freezes Reserve/Create/Spawn/Exec admission, cancels native execution,
waits pending startup locks and queued process workers, stops every owned process
group, drains supervisors, and destroys resources. A native startup already
underway must finish so cleanup can destroy its eventual allocation; it cannot
publish a usable result once shutdown starts. Failed cleanup retains native ownership
and returns an error; retry Shutdown before unloading. Command errors can be
returned after complete resource release; repeating Shutdown then succeeds. The terminal instance
never restarts. Host ordering is stop submissions, await Shutdown, then unload
the ABI/module runtime. The SDK shutdown timeout alone is not this barrier.
Live local execution uses `StartExec(SpawnRequest)` with a Process reservation,
`ReadOutput(ProcessRef, sequence)` for replayable binary stdout/stderr batches,
and `ReleaseOutput(ProcessRef)` after completion. Each execution owns its native
collector, so cancellation joins its own cleanup without waiting for another
running command. Combined output is capped at 1 MiB per execution, chunks at
8 KiB, batches at 64 KiB, and retained live/output handles at 32 per module.
Nonzero exits remain results. Cancellation is acknowledged only after kill/reap;
failed cleanup retains native ownership for Cancel, Close or Shutdown retry.
Release refuses running or unacknowledged cleanup. Resource Close retires its
journals after stream cleanup is acknowledged. Streaming is currently available
for local passthrough resources; other providers explicitly refuse it.

Workspace file transfer uses the bounded Begin/Read/Write/Finish/Abort operations
above. MicroVM configuration and streaming for other providers remain subsequent
slices.

Operations serialize within each resource; unrelated resources have independent
locks. Spawn uses an owned local process group on Unix and a Job Object on
Windows for local commands, never legacy pid-file detach helpers. Remote SSH
process identifiers remain attached to the resource and use the sandbox's stop
operation for cancellation and close. Capabilities distinguishes Create
backends from supervised execution backends. Exec/Spawn support passthrough and
Docker on Unix and Windows; namespace execution remains Linux-only.
Unsupported operations fail explicitly without fallback. Legacy library APIs
remain available. A detached process can be cancelled after Spawn returns. Close fences new
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

AnalyzeShell removes quoted heredoc bodies before segment analysis. Its
redirection fact ignores all heredoc bodies, while hidden-execution analysis
retains expansion-aware behavior for unquoted bodies. It returns segments and
hidden-execution/redirection facts. Authorization,
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
