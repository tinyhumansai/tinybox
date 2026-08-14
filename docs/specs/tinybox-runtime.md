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

A **template is a named snapshot**. No separate type exists, which is why
`WorkspaceSource::Snapshot` covers both resuming a box and starting from a
template — the whole feature is a name-to-digest index.

Templates live in their own file rather than in the box document. Extending
that document would change its shape and stop an older store from loading,
orphaning every box in it; a second file needs no migration and cannot break
the first.

## Time and expiry

Expiry needs to know when a box was created, so time enters the model through a
`Clock` trait rather than `SystemTime::now` scattered through the code — a test
that waits an hour for a box to expire is not a test anyone will run.

`BoxInfo::created_at` is an `Option`. A store written before tinybox tracked
time has no timestamp, and defaulting to the epoch would make every existing box
look decades old and be destroyed by the first reap — exactly the failure a
compatibility default is supposed to prevent. A box whose creation time is
unknown never expires.

Reaping is an explicit `tinybox reap` rather than a background timer, because
tinybox has no long-running process to hold one. Claiming otherwise would leave
boxes alive that the model says are gone. One box failing to destroy does not
stop the rest.

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

`unsafe` is forbidden across the whole workspace, with **no exception**. ADR
0003 expected the namespace backend to need it; ADR 0005 records why it did
not. The split still earns its keep by keeping backend dependencies out of the
released `cdylib` and each backend independently testable.

```text
crates/
├── tinybox-core/     # this specification; unsafe forbidden      (M1, M2)
├── tinybox-host/     # LocalHost                       (M2)
├── tinybox-ssh/      # SshHost                         (M4)
├── tinybox-sync/     # fingerprinting and transfer     (M4)
├── tinybox-docker/   # DockerSandbox                    (M3)
├── tinybox-linux/    # NamespaceSandbox                (M6)
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

## The Docker backend

The first backend that confines anything. It declares `IsolationLevel::Kernel`,
`SnapshotSupport::Filesystem`, `Fork`, and `ResourceLimits`.

It does **not** declare `PauseResume`, even though `docker pause` exists,
because the `Sandbox` trait has no method that would reach it — a capability no
caller can invoke is a claim with nothing behind it.

Every operation is a `docker` command run through the sandbox's `Host` rather
than a call to a local socket, which is what makes Docker-over-SSH fall out of
composition in M4. ADR 0004 records the tradeoff.

| Concern | How |
| --- | --- |
| Lifetime | A detached container held open by `sh -c 'while :; do sleep 86400; done'`. A container exits when its entrypoint returns, and an exited container cannot be `exec`-ed into. |
| Image requirement | Any image with a `sh`. Distroless images do not work, and that is a real constraint rather than a bug. |
| `OciImage` | The image reference. |
| `LocalDir` | Bind-mounted at `/workspace`, which also becomes the working directory, over a small base image. |
| `Snapshot` | The committed image. |
| `GitRepo` | Refused by name — no clone step exists yet. |
| Limits | `--memory`, `--cpus`, `--pids-limit`. Disk is **not** applied: `--storage-opt size=` works on a minority of storage drivers, and a flag that silently does nothing on most systems is worse than an honest omission. |
| Network | `Denied` → `--network none`. Docker has no outbound-only mode, so `Egress` uses the default bridge; nothing is published inbound because tinybox never passes `--publish`. |
| State | Read from `docker inspect`, not from the store. A container can be stopped or removed by anything with daemon access, and reporting a stale `ready` would send commands to a box that is gone. Docker's `running` maps to `Ready`, because a tinybox box is `Running` only while a command executes and the keepalive loop is not a command. |

### Snapshot identifiers

`docker commit` prints `sha256:<64 hex>`, which is not a valid tinybox
identifier — `:` is outside the permitted set. A snapshot id is therefore
`sha-` plus the first twelve hex characters of the digest. Docker resolves that
short form as an image reference, so **no snapshot registry is needed**: the
identifier is the whole record.

### Namespaces

Box identifiers are unique within a `Store`; Docker container names are unique
across a whole daemon. Those are different scopes, so two stores that both
allocate `box-0` would fight over one container name. Containers are therefore
named `tinybox-<namespace>-<box id>`, with the namespace defaulting to
`default` and settable per sandbox.

This was found by the live suite rather than by review, and it is a real
multi-user constraint, not a test artifact.

## Reaching another machine

`SshHost` wraps an inner host — normally `LocalHost` — and prefixes commands
with `ssh`. That inherits the user's existing configuration, keys, agent, jump
hosts, and connection multiplexing, none of which an embedded SSH client would
get for free. It also composes: an `SshHost` over another reaches through a jump
box with no code that knows what a jump box is.

### Quoting is the one place the guarantee is rebuilt by hand

tinybox passes argument vectors precisely so no backend has to quote and no
caller can inject through a filename. **SSH breaks that**: its exec channel
carries a command *string* which the remote login shell then parses. That is
true of the protocol, not of shelling out — an SSH library would face it too.

So `crates/tinybox-ssh/src/host/quote.rs` is the one place in tinybox where a
bug is a command-injection bug. It is a pure function for that reason, pinned by
an exhaustive unit suite, a property test that round-trips every metacharacter
through a local `sh`, and a live test that round-trips the same strings through
a real SSH connection and a real remote login shell.

Two smaller decisions worth recording:

- `BatchMode=yes` always. Without it a missing or rejected key makes `ssh`
  prompt, and a prompt in a program nobody is watching is a hang rather than a
  failure.
- `cd <dir> && <command>` rather than `;`. A missing directory fails the command
  instead of running a build somewhere unexpected.
- Host key checking is never disabled. `accepting_new_host_key` is opt-in and
  accepts an *unknown* key; it does not ignore a *changed* one, which is the
  case that means something is actually wrong.

`ssh` exits `255` when it fails and otherwise passes the remote status through,
so a remote command that genuinely exits `255` is indistinguishable from a
connection failure. That is a property of the protocol, and it is why connection
problems are read from stderr rather than inferred from the code.

## Moving a workspace

`Fingerprint` is a blake3 merkle over a tree: every file's relative path, its
executable bit, and its contents, folded in sorted path order. Sorting is what
makes it reproducible — directory iteration order is not stable, and an unstable
fingerprint would report a change every run and defeat the point.

Modification times are deliberately **not** hashed. A checkout, a rebase, or a
`touch` changes them without changing content, and treating that as a change
would resend an identical tree.

The fingerprint is recorded **on the far side**, in a `.tinybox-fingerprint`
file beside the workspace, rather than in local bookkeeping. Local bookkeeping
goes stale the moment the remote machine is rebuilt or the directory is deleted,
and a stale record causes the one failure that matters: a skipped transfer that
should have happened. An unreadable or missing marker reads as "nothing", so an
unrecognizable state fails towards sending.

Transfer is an uncompressed tar built in-process and piped to `tar` on the far
side, so the only things that have to exist over there are `tar` and `mkdir` —
not rsync, and not a tinybox agent. That matters because the far side is
frequently a container image somebody else built.

### What is left behind

Exclusions come from the workspace's own `.gitignore`, plus a `.boxignore` read
afterwards so its rules win — including `!` lines that put back something git
ignores but a running box needs, such as a `.env`.

The list is not invented. A repository already records what it considers
derived, maintained by people who care about it. A Rust checkout's `target/` or
a Node one's `node_modules/` is usually most of its bytes and none of its value,
and every one of those bytes would otherwise cross the network once and be
hashed on every run after.

Gitignore semantics are more than globs — negation, anchoring, directory-only
patterns, `**` spanning directories, and precedence between all of it. A subset
that is *nearly* right silently drops files a caller expected to send, which is
worse than sending too many, so the `ignore` crate is used rather than a
hand-rolled matcher.

Only the ignore files at the workspace root are read. Git also honors one in
every subdirectory; tinybox does not, because the transfer is of one tree to one
destination and a nested rule set would make the fingerprint depend on files
that are themselves being filtered.

The exclusions are part of the fingerprint's identity: two runs excluding
different things describe different trees, and must not be mistaken for the same
one.

**This is whole-tree transfer with a skip, not a per-file delta.** When a tree
does change, all of it is sent. A real delta needs rsync's rolling checksum or
an agent on the far side to negotiate with; the skip is the win that matters for
an edit-run loop and the one available without either.

Symbolic links are skipped rather than followed: following them can leave the
tree entirely — a link to `/etc` would pull host configuration into the transfer
— and can loop forever on a cycle.

## Ports

Ports are named in `BoxSpec` and applied at creation, because that is the only
moment a container can gain one. Modelling them as a later operation would
promise something no backend can deliver, so `PortForward` is declared by Docker
on that basis.

Nothing is published when the network is denied: a container with no network has
nowhere for a published port to lead, and Docker refuses the combination. The
denial wins, being the stricter of the two.

Forwarding a **remote** box's port back to the local machine is deferred. It
needs `ssh -L`, a long-running process with a lifetime, which `Host::run`'s
run-to-completion shape cannot express — that is a real design question, not an
oversight, and it belongs with the warm-pool work in M5.

## The namespace backend

Rootless kernel isolation with no daemon, no root, and no privileged component
of tinybox's own. It declares `IsolationLevel::Kernel`, and nothing else.

| Concern | How |
| --- | --- |
| Namespaces | user, pid, ipc, uts, cgroup always; net unless the policy allows egress |
| Root filesystem | `/usr` read-only plus merged-`/usr` symlinks, a fresh `/proc`, a `/dev`, and a `tmpfs` `/tmp` |
| Host configuration | Four files, not all of `/etc`: `passwd`, `group`, `resolv.conf`, `ssl/certs`. Binding the whole directory would hand the box every credential and host key the user can read. |
| Workspace | The one writable bind, mounted at `/workspace`, which is also the working directory |
| Environment | Cleared, then rebuilt from the box's and the command's. The caller's environment routinely holds tokens. |
| Limits | `systemd-run --user --scope`, the only route an unprivileged process has to a delegated cgroup — and therefore opt-in |
| Sources | `LocalDir` only. There is no image machinery: this backend binds a directory the caller already has. |

Two flags are part of the boundary and easy to overlook: `--die-with-parent`,
without which a sandbox outlives the box it belongs to, and `--new-session`,
without which the sandboxed process can inject keystrokes into the caller's
terminal through `TIOCSTI`.

### A box is a record, not a container

There is no long-running sandbox process. Each command is a fresh `bwrap` over
the same workspace, so **writes outside the workspace do not survive between
commands**. That is why this backend declares no snapshot support and no
forking: there is no persistent filesystem to capture.

It is a real difference from Docker, and the live suite asserts it rather than
leaving it implied.

### Why bubblewrap rather than raw syscalls

ADR 0003 reserved this crate as the one place `unsafe` would be allowed. It was
not needed. Modern Ubuntu sets
`kernel.apparmor_restrict_unprivileged_userns=1`, which stops an unconfined
binary from creating a user namespace at all; `bwrap` ships a profile that
permits it. A hand-written backend would fail on the most common Linux
distribution — the worst failure mode for a security boundary, unavailable
exactly where it is most needed. ADR 0005 records this in full.

### Not shipped

A seccomp allowlist and landlock were both named in the original plan for this
backend. `bwrap --seccomp` takes a compiled BPF program that this backend does
not build, and landlock is not reachable through `bwrap` at all. Neither
shipped, and neither is claimed.

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

Adding a field to a stored type is a compatibility question: `ports` and
`stdin` are `#[serde(default)]` so a store written by an earlier build still
loads. Failing to read it would orphan every box a user already had.

Two things protect the file, and they solve different problems. Writes are
**atomic** via a temporary file and a rename, so a reader never sees a partial
document. Read-modify-write sequences are **locked**, because atomicity alone
does not stop two processes from both reading the same document, each adding a
box, and the second rename discarding the first.

The lock is advisory and held by the kernel, so a crashed process releases it —
a hand-rolled lockfile would strand one behind a crash and need stale-lock
detection that is its own source of bugs.

Allocating an identifier and recording it are still two operations, and the lock
covers each but not the gap between them. `store::insert_new` catches the
resulting collision and retries with the next free name, so a race becomes a
retry rather than a spurious failure to whoever was creating a box.

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

Under the microVM backend, several of the deferred items below became
answerable and were still deferred — for a reason recorded in ADR 0006: the
guest boots an initramfs rather than a disk image, so there is no rootfs to
stream and no snapshot to restore. What that buys is a boot measured in
hundreds of milliseconds with no image build at all; what it costs is that
nothing the guest writes survives the machine.

Deliberately deferred, with reasons:

- **Firecracker snapshot and restore.** The reason to reach for a VMM at scale,
  and unbuilt here. `MicroVmSandbox` declares `SnapshotSupport::None` so that
  nothing pretends otherwise, which is rule 1 doing its job.
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
- ADR 0006 — a microVM boots an initramfs, not a disk image
- `docs/specs/tinybus-module-release.md` — the module release contract
