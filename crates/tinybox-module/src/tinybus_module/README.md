# TinyBox module

The native module owns sandbox providers, box identifiers, detached processes,
and their lifetimes. Clients depend on `tinybox-bus`, whose only production
dependency is serde. It contains serialized vocabulary, no runtime or TinyBus
connection. `tinybox-module::bus` re-exports that vocabulary for compatibility.

## Public surface

The interface is `ai.tinyhumans.tinybox.Box` at
`/ai/tinyhumans/tinybox/Box`. Arguments below are positional;
`Describe` retains its original zero-argument shape and string result.

| Method | Argument | Result |
| --- | --- | --- |
| Describe | none | Original version/backend summary |
| Shutdown | none | unit |
| Capabilities | none | ModuleCapabilities |
| JailStatus | none | JailStatus |
| Reserve | ReserveRequest | ResourceId |
| Create | CreateRequest | ResourceInfo |
| RunDocker | DockerRunRequest | DockerRunOutput |
| RunDockerWithoutWorkspace | DockerRunRequest with an empty `workspace` | DockerRunOutput |
| DockerStatus | DockerStatusRequest | DockerStatus |
| CleanupDocker | CleanupDockerRequest | CleanupDockerOutput |
| Forward | ForwardRequest | ForwardInfo |
| CloseForward | CloseForwardRequest | unit |
| Exec | ExecRequest | ExecOutput |
| Inspect | ResourceId | ResourceInfo |
| Close | ResourceId | unit |
| Spawn | SpawnRequest | ProcessRef |
| StartExec | SpawnRequest | ProcessRef |
| StartJailedExec | SpawnRequest, NativeJailConfig | ProcessRef |
| ReadOutput | ProcessRef, cursor | OutputBatch |
| ReleaseOutput | ProcessRef | unit |
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
| ResolveLocalGrants | ResolveLocalGrantsRequest | LocalGrants |
| SelectShell | SelectShellRequest | ShellInvocation |
| StartShellExec | SpawnRequest, SelectShellRequest | ProcessRef |
| StartNativeShellExec | ShellExecRequest | ProcessRef |
| ValidateDockerPolicy | DockerPolicyRequest | DockerPolicyReport |

Capabilities advertises contract version 1.20; 1.0 denotes the original
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

Version 1.8 adds `RunDocker` for one-shot commands. TinyBox owns the local
Docker CLI invocation, `--rm` container lifetime, and bounded output collection;
the caller supplies the existing image, network, memory, CPU, rootfs, read-only
mount, capability-drop, environment, label, and timeout settings. Runtime is
capped at 24 hours. It does not create a long-lived resource or fall back to a
host command. The caller remains responsible for validating requested network
and mount policy before sending the request.

Version 1.9 adds bounded `DockerStatus` and `CleanupDocker` operations. The
status probe reports whether the module host's daemon responds before the
requested deadline. Cleanup lists and stops containers matching the requested
`key=value` label and reports the number of IDs submitted to Docker. Invalid
labels and deadlines are refused; daemon or cleanup failures return a stable
module error rather than claiming successful cleanup.

Version 1.10 adds `RunDockerWithoutWorkspace` for Docker runtimes that do not
mount a host workspace. It accepts the same bounded Docker settings as
`RunDocker`, requires an empty `workspace`, and omits both the workspace bind
mount and working-directory override. `login_shell` defaults to false for
existing callers; when true, the command runs through `sh -lc` rather than
`sh -c`, preserving login-shell runtime behavior. All other image, network,
resource, rootfs, read-only mount, capability-drop, environment, label, output,
and timeout behavior remains shared with `RunDocker`.

Version 1.20 adds optional `allow_unix_paths` to `ResolveLocalGrantsRequest`
and `unix_paths` to `LocalGrants` and `NativeJailConfig`. Unix callers can
preserve canonical non-UTF8 paths as raw bytes after host approval. Empty
byte groups retain established wire payloads. Module validation checks all
string and byte grants against the same total limit and enforcement policy.
Configured Rustup and selective Cargo state remain read-only; native shell
execution preserves nonempty `RUSTUP_HOME` and `CARGO_HOME` as OS values.

Version 1.18 adds `ValidateDockerPolicy(DockerPolicyRequest) -> DockerPolicyReport`,
the standalone form of the 1.17 check: it lists every way a run's network mode,
workspace and read-only mounts would weaken isolation, without a daemon or a
container. It also adds `hide_window` to `ShellExecRequest` (Windows: no
console window for the shell child; ignored elsewhere).

Version 1.17 makes both Docker run members refuse a request that uses the
`host` network or bind-mounts `/`, `/etc`, `/var/run/docker.sock`, `/proc` or
`/sys` (as workspace or read-only mount) with `InvalidDockerRun`. The caller
still owns choosing the policy; the module no longer trusts it to be safe.

Version 1.11 adds `ResolveLocalGrants` for discovering canonical read-only and
writable local grants under a caller-supplied protected-path floor. Git
configuration discovery follows Git's XDG config-home selection and supports
include chains up to Git's ten-level limit.

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
Live passthrough execution uses `StartExec(SpawnRequest)` with a Process reservation,
`ReadOutput(ProcessRef, sequence)` for replayable binary stdout/stderr batches,
and `ReleaseOutput(ProcessRef)` after completion. Each execution owns its native
collector, so cancellation joins its own cleanup without waiting for another
running command. Combined output is capped at 1 MiB per execution, chunks at
8 KiB, batches at 64 KiB, and retained live/output handles at 32 per module.
Nonzero exits remain results. Cancellation is acknowledged only after kill/reap;
failed cleanup retains native ownership for Cancel, Close or Shutdown retry.
Release refuses running or unacknowledged cleanup. Resource Close retires its
journals after stream cleanup is acknowledged. Streaming is currently available
for local and SSH passthrough resources and Docker resources; other sandbox
providers explicitly refuse it.

Workspace file transfer uses the bounded Begin/Read/Write/Finish/Abort operations
above. MicroVM configuration and observed namespace execution remain
subsequent slices.

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

## Native directory-jail execution

`StartJailedExec` (wire 1.7) uses the local directory resource as its writable
root. The module canonicalizes every approved extra grant, rejects missing
paths and working directories outside the root, and performs the requested
enforcement preflight before consuming process admission. `Enforced` refuses
partial constraints; `Declared` requires an explicit host decision using
`JailStatus`. Neither mode admits the no-op or unavailable backend. A caller
requiring the process-isolation security floor sets `require_process_isolation`.
The host retains credential-path exclusions and approval policy.

The jail owns a separate native collector for each execution. Output replay,
Cancel, ReleaseOutput, Close and Shutdown use the same retained cleanup barriers
as StartExec. Windows rejects this operation until its native jail has a
supervised child bridge; explicit ordinary local execution remains available.


## Observed SSH execution

`StartExec` on an SSH passthrough resource uses a separate SSH supervisor and
native collector for each execution. Binary stdin, stdout and stderr retain
their bytes. Cancellation and close acknowledge the remote process group's
cleanup before retiring the execution; failed acknowledgements keep the owner
available for retry. Streaming never falls back to collected `Exec` output.
Native-jail requests remain local operations and reject SSH resources.

The compiled-artifact SSH fixture runs generated remote commands through a
checked-in local transport script. It verifies that this script is selected
before admitting a target, so the test does not contact an SSH server:

```sh
cargo build -p tinybox-module
PATH="$PWD/crates/tinybox-module/tests/fixtures:$PATH" \
TINYBOX_TEST_MODULE="$PWD/target/debug/libtinybox.so" \
cargo test -p tinybox-module --test module_e2e -- --ignored
```

Use `libtinybox.dylib` for the artifact on macOS. Each artifact fixture loads an
independent library path so concurrent module initialization stays isolated.


## Observed Docker execution

`StartExec` on Docker resources uses the existing box/store identity and a
separate host collector and cleanup journal for each execution. The provider
reserves a private owner token before launching its container-side supervisor.
Cancellation waits for the supervisor's process-group reap acknowledgement;
lost acknowledgement or receipt-release replies retain enough state for retry.
Cancelling one execution leaves other executions in the container running.

Resource Close may remove the entire container to retire an unreachable
waiter. After the provider acknowledges removal, the module retires each
execution view's remote journal and still drains its native CLI owner. A failed
native drain keeps the resource available for Close retry without repeating
container destruction. Resource reservations supply unique Docker namespaces,
so two resource-local stores cannot collide on their first box identifier.
`StartJailedExec` rejects Docker resources instead of executing them locally.

The compiled-artifact Docker fixture uses the checked-in local `docker` script
alongside the SSH fixture in the command above. It executes the generated
supervisor shell and verifies stream behavior and scoped cancellation without
a Docker daemon; it does not establish container isolation. Provider live tests
cover actual Docker when a local daemon is available.

### Local grant discovery

Contract 1.11 adds `ResolveLocalGrants`. The caller supplies its operator home,
`LocalGrantConfig`, and `ProtectedPaths` floor. TinyBox resolves existing paths,
canonicalizes symlinks, discovers toolchain homes and Git include chains, and
returns read-only and writable grants. Discovery does not start a process or
make an approval decision. Credential roots exclude both descendants and
ancestors; a grant on the operator home cannot expose `.ssh`. `/proc` is granted
only by the explicit `allow_proc` flag. Both requested names and canonical
targets must clear the floor; configured roots preserve both their alias and
canonical spellings. Rejected Git config files are never traversed, and ignore
pattern files are granted directly without parsing configuration includes.
Shared Cargo Git and registry dependency caches are read-only because their
build scripts can execute in later host builds; writable extras cannot promote
those caches or recursively expose them. Automatically discovered read-only
toolchains and Git configuration also cannot be promoted by writable extras;
Cargo executables and launch configuration remain protected even if discovery
is disabled. Mutable toolchain operations need separately authorized disposable
state. Commands that fetch dependencies
need a separately authorized disposable Cargo home. Hosts must supply their complete floor
and apply authorization before using the returned grants in `StartJailedExec`.

Directory grants are inspected recursively for protected component names and
component pairs before admission. The scan preserves requested alias names,
does not follow nested symlinks, and rejects symlinks named as a protected
pair's first component. Inspection errors, more than 1,000,000 entries, or
more than 128 directory levels refuse the grant. This also applies to automatic
system toolchain roots, which may therefore be omitted. Discovery is a
point-in-time snapshot: hosts must prevent concurrent mutation and creation of
protected entries within a granted tree, or use isolated disposable state.
It does not install a kernel deny rule for filenames created later.

Git include aliases retain their logical parent. Empty XDG_CONFIG_HOME is
unset; unsupported ~user/ and %(prefix)/ expansion rejects complete discovery.
[Contract specification](../../../../docs/specs/local-grants.md).

### Platform shell discovery

Contract 1.12 adds `SelectShell`. The request carries command text and an optional
pipeline-status preservation flag. Unix selects Bash at a standard path with
`set -o pipefail` by default, or /bin/sh without that Bash-only flag when Bash is
absent. Unix uses non-login `-c` to avoid loading login profiles before the
payload. Windows selects `SystemRoot/System32/cmd.exe` from the parent
environment independently of payload PATH and COMSPEC overrides. Its
`/D /E:ON /V:OFF /S /C` switches disable registry AutoRun hooks and strip one
explicit outer wrapper around the raw command-line payload.
Quoted executable/argument pairs, redirection paths and percent expansion remain
inside that wrapper.
The result includes Windows bootstrap environment names, never their values.
Selection does not execute a command, authorize access or provide confinement;
hosts continue to execute through the module. Native providers can use the
shared quote-preserving TinyBox command builder.

Windows explicitly enables extensions and disables delayed expansion.
Unix builders remove BASH_ENV, ENV, SHELLOPTS, BASHOPTS and POSIXLY_CORRECT;
ShellInvocation returns those removal names. Bash uses -p to ignore exported functions.
Discovery checks standard Bash paths on every call. Providers apply the
removals after approved environment overrides.

Contract 1.13 adds `StartShellExec(SpawnRequest, SelectShellRequest)`. Supply an
empty argv in SpawnRequest; its resource, cwd, environment and stdin retain
their usual meaning. This operation supports local passthrough resources only,
because selection describes the module machine's shell. It uses the native
builder, including Windows raw arguments, and the existing supervised bounded
output, cancellation and cleanup lifecycle. Read and release its journal with
ReadOutput and ReleaseOutput. Retries must preserve both requests exactly.

## Native shell execution

Contract 1.14 adds `StartNativeShellExec(ShellExecRequest) -> ProcessRef` for local
passthrough resources. It composes platform shell selection with safe parent
environment snapshots, approved overrides, private scratch, bounded pipes and
owned timeout/cancellation cleanup. `ReadOutput` retains scratch until
`ReleaseOutput` or resource close acknowledges cleanup. Explicit native jail
requests refuse unavailable enforcement; remote/Docker providers refuse this
operation. State directory authorization and Windows private parent ACLs belong
to the caller. See [the native shell contract](../../../docs/specs/native-shell-execution.md).

Version 1.19 adds `NetworkPolicy::Allowlist` and the `SandboxEvent` vocabulary
without a new member; see `docs/specs/contract-1-19.md`.
