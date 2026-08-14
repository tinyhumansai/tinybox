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
| M4 — `SshHost`, fingerprint sync, port forwarding | next |
| M5 — snapshots, templates, lifecycle policy, warm pool | planned |
| M6 — `NamespaceSandbox` (rootless userns, cgroup v2, seccomp) | planned |
| M7 — `MicroVmSandbox` (Firecracker) | deferred |

Two sandboxes exist. `passthrough` confines nothing, so `tinybox create` warns
and `tinybox inspect` prints `UNSAFE`. `docker` clears the isolation floor and
is a defensible place for code you do not trust.

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

`unsafe` is forbidden across the workspace. When the namespaces backend lands it
will be confined to `tinybox-linux`, the only crate permitted to relax that —
see [ADR 0003](docs/adr/0003-workspace-split-to-contain-unsafe.md).

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
TINYBOX_LIVE_DOCKER=1 cargo test -p tinybox-docker --test live_docker
```

They assert isolation *negatively* — that a box cannot see host processes, that
a denied network really has only loopback — because a positive assertion would
pass just as happily against a sandbox that confines nothing.

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
