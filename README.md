# tinybox

A workspace containerization runtime: tinybox encapsulates a *box* — an
isolated place where code runs — and makes the isolation something a caller can
inspect before relying on it.

TinyBus loads modules as native libraries into the host process, and is blunt
about the consequence: *"in-process modules are trusted code with the host's
full address-space privileges."* tinybox is where code the operator does **not**
trust goes instead.

Two workloads share one abstraction: ephemeral boxes for short-lived,
untrusted, agent-generated code, and persistent boxes for developer workspaces
that are stopped, resumed, and forked over days.

## Reach and confinement are separate

SSH answers *which machine* a process runs on. Docker answers *what confines
it*. tinybox keeps them as independent axes joined by a `Placement`:

```text
Host — reach                 Sandbox — confinement
├── local                    ├── passthrough
└── ssh                      ├── docker
                             ├── namespace
                             └── microvm
```

Pairings then cost nothing: `ssh` + `docker` is Docker on a remote machine with
no code dedicated to that combination. A box names *two* placements — one for
the runner driving the work, one for the workspace where code executes — so a
local runner can drive a remote workspace.

```rust
use tinybox_core::{BoxSpec, HostRef, Placement, SandboxRef, WorkspaceSource};

let workspace = Placement::new(HostRef::new("builder-01")?, SandboxRef::new("docker")?);
let runner = Placement::new(HostRef::new("local")?, SandboxRef::new("passthrough")?);

let spec = BoxSpec::new(workspace, WorkspaceSource::OciImage("alpine:3".into()))
    .with_runner(runner);

assert!(!spec.is_colocated());
# Ok::<(), tinybox_core::Error>(())
```

## Backends declare what they do

Every sandbox returns a `SandboxCapabilities`, and core refuses undeclared
requests with `Error::Unsupported` rather than degrading silently. A
passthrough sandbox that reported the shape of a microVM would leave a caller
believing untrusted code had been contained when it had not.

```rust
use tinybox_core::{Capability, IsolationLevel, SandboxCapabilities};

let bare = SandboxCapabilities::PASSTHROUGH;
assert_eq!(bare.isolation, IsolationLevel::None);
assert!(!bare.is_suitable_for_untrusted_code());
assert!(bare.require("passthrough", Capability::Fork).is_err());
```

`IsolationLevel::Kernel` is the floor for untrusted code.

## Status

| Milestone | State |
| --- | --- |
| M1 — workspace, core model, provider traits, bus adapter | shipped |
| M2 — `LocalHost` + passthrough sandbox, `tinybox` CLI | shipped |
| M3 — `DockerSandbox`, OCI images, snapshots, forking | shipped |
| M4 — `SshHost`, fingerprint sync, published ports | shipped |
| M5 — templates, expiry, `.boxignore`, store locking | shipped |
| M6 — `NamespaceSandbox` (rootless, no daemon, no root) | shipped |
| M7 — `MicroVmSandbox` (Firecracker, own kernel) | shipped |

Four sandboxes exist. `passthrough` confines nothing, so `tinybox create`
warns and `tinybox inspect` prints `UNSAFE`. `docker` and `namespace` both clear
the isolation floor and are defensible places for code you do not trust —
`namespace` without a daemon, without root, and without an image. `microvm`
goes further than either: the guest runs its own kernel under KVM, so a kernel
exploit has nothing to escape into. It needs `firecracker`, a static `busybox`,
and an uncompressed kernel on the host, and it gives back only the command's
output — the guest's filesystem is memory, discarded when the machine resets.

```sh
tinybox create --sandbox microvm --microvm-kernel ~/vmlinux --dir ./project
tinybox --microvm-kernel ~/vmlinux exec box-0 -- /bin/busybox uname -r
6.1.128                            # a kernel the host is not running
```

## Try it

```sh
cargo build -p tinybox-cli
export TINYBOX_STATE_DIR=$(mktemp -d)

# Unconfined, on the local machine.
tinybox create --dir /path/to/project --env CI=true   # -> box-0
tinybox exec box-0 -- echo hello
tinybox rm box-0

# Confined, in a container.
tinybox create --sandbox docker --image alpine:3      # -> box-0
tinybox exec box-0 -- sh -c 'ls /proc | grep -c "^[0-9]*$"'   # a private process table
tinybox inspect box-0
```

```text
id:         box-0
sandbox:    docker
state:      ready
workspace:  alpine:3
runner:     local / docker
isolation:  kernel
untrusted:  safe
supports:   filesystem snapshots, forking, resource limits
```

Snapshot a box and branch it — the fork inherits the parent's filesystem and
writes to it do not reach back:

```sh
tinybox exec box-0 -- sh -c 'echo captured > /marker'
snap=$(tinybox snapshot box-0)        # -> sha-30ff5506ef1d
fork=$(tinybox fork "$snap")          # -> box-1
tinybox exec "$fork" -- cat /marker   # -> captured
```

Or run one command and leave nothing behind:

```sh
tinybox run --sandbox docker --image alpine:3 -- echo once
```

## Somewhere else

`--host` changes *where*, and nothing else. Every sandbox already works
remotely, because reach and confinement were never entangled:

```sh
# A container on another machine. No Docker-side code exists for this pairing.
tinybox --host ssh://builder@example.com create --sandbox docker --image alpine:3
tinybox --host ssh://builder@example.com exec box-0 -- hostname
```

Send a working tree over, and watch the second send cost nothing:

```sh
tinybox --host ssh://builder@example.com sync --to /srv/work
# sent       9f2c0e1b…   4096 bytes
tinybox --host ssh://builder@example.com sync --to /srv/work
# unchanged  9f2c0e1b…
```

Nothing was listed on that command line: `sync` reads the workspace's own
`.gitignore`, so `target/` and `node_modules/` stay behind because the project
already said they are derived. A `.boxignore` beside it can override — including
`!.env` to put back something git ignores but a running box needs. `--no-ignore`
sends everything.

Everything not named on the command line is left to your `~/.ssh/config`, which
is where jump hosts and multiplexing already live. A throwaway machine has no
config entry, so the few settings it needs are flags:

```sh
tinybox --host root@10.0.0.5 --ssh-port 2222 --ssh-identity ~/keys/builder \
        --accept-new-host-key exec box-0 -- uname -a
```

`--accept-new-host-key` trusts an *unknown* key; it never ignores a *changed*
one, which is the case that means something is wrong.

Publish a port with `-p`:

```sh
tinybox create --sandbox docker --image nginx -p 8080:80
```

## Without a daemon

`namespace` isolates a directory you already have, using Linux namespaces
directly. No daemon, no root, no image, and nothing of tinybox's own running
privileged:

```sh
tinybox create --sandbox namespace --dir ./my-project      # -> box-0
tinybox exec box-0 -- /bin/sh -c 'ls /proc | grep -c "^[0-9]*$"'   # a handful, not hundreds
tinybox exec box-0 -- /bin/sh -c 'test -e /home && echo leaked || echo absent'
```

It needs `bubblewrap` installed. A box here is a record and a bound directory
rather than a running container, so **writes outside the workspace do not
survive between commands** — which is why it declares no snapshot support. See
[ADR 0005](docs/adr/0005-namespaces-through-bubblewrap.md) for why it drives
`bwrap` instead of calling `clone` directly, and why no `unsafe` was needed.

## Templates

Provisioning is the slow part of making a box, so do it once and give the result
a name. A template is just a named snapshot:

```sh
tinybox create --sandbox docker --image alpine:3     # -> box-0
tinybox exec box-0 -- apk add --no-cache build-base  # the slow bit
tinybox template save build-env --from box-0
tinybox template ls
# build-env    sha-2d0325276589

# Every box after this starts with the toolchain already installed.
tinybox create --sandbox docker --template build-env
```

## Expiry

Ephemeral boxes carry a ttl. `reap` acts on it:

```sh
tinybox reap --dry-run
# would reap   box-3
tinybox reap
# reaped       box-3
```

It is a command rather than a background timer, because tinybox has no
long-running process to hold one — so run it from cron if you want it periodic.
A box created before tinybox tracked creation times is never reaped, since
guessing its age would mean destroying work on the strength of a missing field.

Boxes outlive the process that made them, so `create` and `exec` are separate
invocations, and a box remembers which sandbox it belongs to — there is no
`--sandbox` on `exec`. Records live in `$TINYBOX_STATE_DIR`,
`$XDG_STATE_HOME/tinybox`, or `~/.local/state/tinybox`. A command that fails
sets tinybox's exit code to its own; a tinybox failure uses `70`, so the two are
never confused.

Container names are `tinybox-<namespace>-<box id>`; pass `--namespace` when
another tinybox shares the daemon, since box ids are only unique within one
store.

## Layout

```text
crates/
├── tinybox-core/            # the model, provider traits, and policy
│   ├── src/lib.rs           # crate docs + the entire public re-export surface
│   ├── src/error/           # crate-wide `Error` and `Result<T>`
│   ├── src/identity/        # validated BoxId, SnapshotId, HostRef, SandboxRef
│   ├── src/capability/      # SandboxCapabilities, IsolationLevel, SnapshotSupport
│   ├── src/spec/            # BoxSpec, Placement, Resources, Lifecycle
│   ├── src/runtime/         # the Host and Sandbox traits
│   ├── src/passthrough/     # the sandbox that confines nothing
│   ├── src/store/           # the Store trait and an in-memory one
│   ├── tests/public_api.rs  # consumer-perspective regression suite
│   └── examples/basic.rs
├── tinybox-host/            # reach: LocalHost today, SshHost in M4
│   └── src/local/           # the only code that spawns a process directly
├── tinybox-docker/          # confinement: containers, snapshots, forking
│   ├── src/sandbox/args.rs  # pure `docker` command construction
│   └── tests/live_docker.rs # gated behind TINYBOX_LIVE_DOCKER
├── tinybox-ssh/             # reach: another machine
│   ├── src/host/quote.rs    # the one place a bug is an injection bug
│   ├── tests/composition.rs # the receipt for "Docker over SSH costs nothing"
│   └── tests/live_ssh.rs    # gated behind TINYBOX_LIVE_SSH
├── tinybox-linux/           # confinement: rootless namespaces, no daemon
│   └── tests/live_namespaces.rs # gated behind TINYBOX_LIVE_NAMESPACES
├── tinybox-sync/            # fingerprinting, exclusions, tar-over-stdin transfer
├── tinybox-cli/             # the `tinybox` binary
│   ├── src/command/         # argument parsing and dispatch
│   ├── src/store/           # the JSON box store, written atomically
│   └── tests/binary.rs      # drives the real binary end to end
└── tinybox-module/          # cdylib, TinyBus ABI v1  ->  libtinybox.so
    ├── src/tinybus_module/  # bus interface, setup, ABI exports
    └── examples/            # verify_module, verify_github_release
vendor/tinybus/              # pinned TinyBus git submodule (build-time SDK)
docs/
├── specs/tinybox-runtime.md # the runtime specification
├── plans/                   # implementation-ordered delivery plans
└── adr/                     # immutable architecture decision records
```

`unsafe` is forbidden across the whole workspace, with **no exception**. [ADR
0003](docs/adr/0003-workspace-split-to-contain-unsafe.md) expected the namespace
backend to need it; [ADR
0005](docs/adr/0005-namespaces-through-bubblewrap.md) records why it did not.

## Development

Nothing compiles until the submodule is initialized:

```sh
git submodule update --init --recursive
```

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo build --all-targets --all-features
cargo test --all-features
```

Those four are exactly what CI runs. Extras:

```sh
cargo run -p tinybox-core --example basic
cargo build --release -p tinybox-module --lib   # produces libtinybox.so
cargo doc --no-deps --all-features              # CI adds RUSTDOCFLAGS="-D warnings"
cargo deny check all                            # supply-chain check; see deny.toml
cargo install cargo-llvm-cov                    # once, before the coverage gate
.github/scripts/check-file-coverage.sh 90 coverage.json
```

The coverage gate requires **90% line coverage in every file individually**, not
in aggregate.

Tests that need a real Docker daemon are gated and named `live_*`, so an
ordinary `cargo test` skips them:

```sh
TINYBOX_LIVE_DOCKER=1     cargo test -p tinybox-docker --test live_docker
TINYBOX_LIVE_SSH=1        cargo test -p tinybox-ssh    --test live_ssh
TINYBOX_LIVE_NAMESPACES=1 cargo test -p tinybox-linux  --test live_namespaces
```

The Docker suite asserts isolation *negatively* — that a box cannot see host
processes, that a denied network really has only loopback — because a positive
assertion would pass just as happily against a sandbox that confines nothing.

The SSH suite starts a throwaway `sshd` in a container with a generated key and
round-trips every shell metacharacter through a real connection and a real
remote login shell. That is the assertion that matters, because SSH carries a
command *string* rather than an argument vector, making quoting the one place in
tinybox where a bug is a command-injection bug.

## Releasing

Run the **Release** workflow from the Actions tab with a `patch`, `minor`, or
`major` bump; use `current` only to resume an interrupted release whose version
commit and tag already exist. The workflow revalidates the workspace, versions
and tags it, builds `tinybox-module` as a TinyBus `cdylib`, and creates a GitHub
release.

Assets follow `tinybox-<version>-<platform>.<tar.gz|zip>` and contain the native
module, its SHA-256 `modules.toml`, the license, and [`MODULE.md`](MODULE.md).
Every release also publishes `checksum.toml`, which TinyBus uses to verify an
archive before extraction. The workflow loads the published Ubuntu archive
through TinyBus's GitHub release API and calls `Describe` before declaring the
release successful.

TinyBus itself is not shipped here; the pinned submodule is the build-time SDK.
The native matrix covers Ubuntu 22.04 and 24.04, Fedora 43 and 44, and rolling
Arch Linux; macOS 15 and 26 on Intel and Apple Silicon; Windows Server 2022 and
2025 on x86_64; and Windows 11 on ARM64. Do not hand-edit the version in
`Cargo.toml` — the workflow owns it.

## Documentation

- [`docs/specs/tinybox-runtime.md`](docs/specs/tinybox-runtime.md) — the runtime
  specification: the model, the capability contract, and the adopted
  optimizations
- [`docs/adr/`](docs/adr/0001-record-architecture-decisions.md) — architecture
  decision records, including [why backends drive a CLI through the `Host`
  trait](docs/adr/0004-drive-backends-through-the-host-trait.md)
- [`AGENTS.md`](AGENTS.md) — repository guidelines for humans and agents
  (`CLAUDE.md` is a symlink to it)
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — how to propose a change
- [`SECURITY.md`](SECURITY.md) — how to report a vulnerability

## License

GPL-3.0-only. See [LICENSE](LICENSE).
