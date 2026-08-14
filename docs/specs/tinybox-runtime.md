# tinybox runtime

Status: accepted. Covers the model and provider contract; backend behavior is
specified per backend as each lands.

## Problem

TinyBus loads modules as native libraries into the host process. Its own
documentation is blunt about what that means: *"in-process modules are trusted
code with the host's full address-space privileges."* The `capabilities` field
in `ModuleManifest` records what a module claims but enforces nothing.

There is therefore nowhere to put code the operator does not trust. tinybox is
that somewhere: it encapsulates a *box* — an isolated place where code runs —
and makes the isolation a property a caller can inspect before relying on it.

Two workloads share the abstraction:

- **Ephemeral** — short-lived, untrusted, agent-generated code. Disposable,
  served from a warm pool, never resumed.
- **Persistent** — a developer workspace that is stopped, resumed, and forked
  over days.

## Reach and confinement are separate concerns

SSH answers *which machine* a process runs on. Docker answers *what confines
it*. These are different questions and tinybox models them as independent axes:

```text
Host — reach                 Sandbox — confinement
├─ local                     ├─ passthrough
└─ ssh                       ├─ docker
                             ├─ namespace
                             └─ microvm
```

A `Placement` pairs one of each. Composition is then free: `ssh` + `docker` is
Docker on a remote machine with no code dedicated to that pairing. Folding both
axes into a single backend enum would instead require a variant per combination
and a new variant every time either axis grows.

## A box names two placements

`BoxSpec` carries `runner` and `workspace` placements independently, because
the agent driving the work and the code being run need not sit together:

| Case | runner | workspace |
| --- | --- | --- |
| Local development | local / passthrough | local / passthrough |
| Untrusted agent code | local / passthrough | local / namespace |
| Remote build | local / passthrough | builder-01 / docker |
| Hardened remote | local / docker | builder-01 / microvm |

`BoxSpec::new` colocates them; `BoxSpec::with_runner` splits them apart.

## Backends declare what they do

Every sandbox returns a `SandboxCapabilities`:

- `isolation`: `None` → `Process` → `Kernel` → `Hardware`, ordered so callers
  can express a floor rather than enumerate acceptable backends.
- `snapshot`: `None` / `Filesystem` / `FilesystemAndMemory`. A container can
  freeze a filesystem but not live memory; only a hypervisor-backed sandbox
  does both.
- a set of the remaining capabilities: `Fork`, `PauseResume`, `PortForward`,
  and `ResourceLimits`.

`ResourceLimits` deserves naming explicitly. A sandbox that cannot cap memory
must decline it rather than accept a `Resources` and ignore it — accepting a
limit that is never applied is the same class of dishonesty as reporting
isolation that does not exist. The passthrough sandbox declines it.

Core checks the declaration before dispatching and returns
`Error::Unsupported { sandbox, capability }`. **A backend must never emulate a
capability it has not declared.** The rule matters most at the weak end: a
passthrough sandbox confines nothing, and if it reported the shape of a microVM
a caller would believe untrusted code had been contained when it had not.

`Kernel` is the floor for untrusted code — the workload must at minimum be
unable to see or signal host processes. `is_suitable_for_untrusted_code`
encodes that single decision so it cannot drift between callers.

## Lifecycle is policy, not machinery

Ephemeral and persistent boxes use identical primitives — create, exec,
snapshot, fork. Only the reaper and the autosnapshot timer read `Lifecycle`:

- `Ephemeral { ttl }` — no autosnapshot; destroyed when the ttl elapses.
- `Persistent { autosnapshot }` — snapshot on a cadence; stop captures and
  archives; resume forks the newest snapshot.

A **template is a named snapshot**. No separate type or storage path exists,
which is why `WorkspaceSource::Snapshot` covers both resuming a box and
starting from a template.

## Defaults

| Setting | Default | Reason |
| --- | --- | --- |
| `NetworkPolicy` | `Denied` | The common case is code with no business making outbound connections, and an accidental default of "open" is noticed only afterwards. |
| `Lifecycle` | `Ephemeral`, 1 hour | Untrusted code should expire on its own. |
| Autosnapshot | 60s when persistent | Matches the cadence a resumable workspace needs without a per-write cost. |
| `Resources` | 2 cores, 2 GiB, 512 pids, 8 GiB | Sized for an agent task, not a build farm. |

Every resource limit must be positive: zero reads as "unlimited" to some
backends and "deny everything" to others, so `validate` rejects it outright.

## Identifiers

Box, snapshot, host, and sandbox names are validated newtypes: non-empty, at
most 64 characters, drawn from `[A-Za-z0-9._-]`, and never `.` or `..`. That
set is the intersection of what a path component, a container name, and a shell
word all accept unquoted, so every downstream backend can interpolate them
without escaping. Validation happens once, at construction.

`ExecRequest` carries an argument vector rather than a command line for the
same reason: no backend has to quote, and no caller can inject through a
filename.

## Non-goals for this specification

- Backend implementation detail — specified per backend as each lands.
- Wire formats for the CLI and the bus interface.
- Scheduling or placement across a fleet. tinybox runs a box where it is told.

## Workspace layout

`unsafe` is forbidden crate-wide. A namespaces backend needs `clone`,
`unshare`, `pivot_root`, and seccomp, so it is confined to its own crate rather
than relaxing the lint everywhere — see ADR 0003.

```text
crates/
├── tinybox-core/     # this specification; unsafe forbidden      (M1, M2)
├── tinybox-host/     # LocalHost (M2), SshHost (M4)
├── tinybox-docker/   # DockerSandbox                    (M3)
├── tinybox-linux/    # NamespaceSandbox; unsafe allowed (M6)
├── tinybox-cli/      # bin `tinybox`                    (M2)
└── tinybox-module/   # cdylib, TinyBus ABI v1                    (M1)
```

Crates appear when they have real content. An empty crate is a placeholder.

## Where a sandbox implementation lives

`PassthroughSandbox` is in `tinybox-core` rather than a backend crate, which
looks like a layering violation and is not. It holds an `Arc<dyn Host>` and
delegates every command to it, so it performs no I/O and adds no dependency.
That delegation is the point: passthrough is generic over reach, so pairing it
with an SSH host in M4 yields "run it over there, unconfined" with no code
naming that combination.

A backend that genuinely touches the operating system — Docker, namespaces, a
VMM — belongs in its own crate, both to keep its dependencies out of the
released `cdylib` and to keep the impure surface small enough that the per-file
coverage gate stays reachable.

## Persistence of box records

A `Sandbox` does not own the fact that a box exists; a `Store` does. The CLI
creates a box in one process and executes in it from another, so the record has
to outlive both.

`Store` is synchronous — every implementation is a memory map or a small local
file, and making it async would push executor choice onto every caller for no
gain. `MemoryStore` serves tests and single-process runs; the CLI's `FileStore`
writes a JSON document atomically, via a sibling temporary file and a rename, so
a reader never observes a partial document.

Identifiers are the lowest free `box-N`. That is reproducible, which the tests
depend on and randomness would destroy, and it keeps names short enough to type.
Deserializing a record re-validates every identifier, so hand-editing the store
cannot introduce a name the constructor would have rejected.

Concurrent writers can still lose an update — last writer wins. Locking is
deferred until there is reason to believe concurrent CLI invocations matter; the
failure mode is a lost record, not a corrupt file.

## Adopted optimizations

Drawn from Firecracker, microsandbox, Box, and crabbox; ordered by
payoff against effort, and filtered to what applies before a microVM exists.

1. **Templates over provisioning scripts** — never install dependencies on the
   critical path.
2. **`.boxignore` derived from `.gitignore`** — exclude build output from
   snapshots. Near-free, and the largest single improvement to fork and resume.
3. **Fingerprint-skip sync** — content-hash the workspace tree, transfer only
   what changed, skip entirely when the root hash matches.
4. **Incremental snapshots** — each snapshot is one overlay layer, so the chain
   *is* the increment.
5. **cgroups v2, never v1** — v1 carries a documented restore-latency penalty,
   making this a performance decision as much as a security one.
6. **Warm pool** of pre-created boxes.

Deliberately deferred, with reasons:

- **Guest-side EROFS/VMDK rootfs.** microsandbox measured a 47× geomean from
  this, but the gain came entirely from deleting a *host FUSE boundary*. Docker
  and namespaces backends have no such boundary — overlayfs is already in the
  host kernel — so that win is already ours. It becomes relevant only under a
  microVM.
- **`MAP_PRIVATE` + UFFD on-demand paging, access-order prefetch, lazy rootfs
  streaming.** All are VMM memory- and disk-restore techniques, meaningless
  before a hypervisor backend exists.
- **Host-side `smoltcp` stack with egress credential substitution.** High
  effort, and TinyBus's `secret::Secret` covers the near-term need.

## Related

- ADR 0002 — host and sandbox are orthogonal
- ADR 0003 — workspace split to contain `unsafe`
- `docs/specs/tinybus-module-release.md` — the module release contract
