# Roadmap

What exists, what is next, and what is deliberately out of scope. See
[`docs/specs/tinybox-runtime.md`](docs/specs/tinybox-runtime.md) for the model
these milestones build out.

## Shipped

- the workspace split, with `unsafe` forbidden everywhere and a single crate
  reserved to relax it later (ADR 0003)
- `tinybox-core`: validated identifiers, `BoxSpec` / `Placement` / `Resources` /
  `Lifecycle`, the `Host` and `Sandbox` traits, and the `SandboxCapabilities`
  contract that makes a backend declare what it really does (ADR 0002)
- `tinybox-module`: the `ai.tinyhumans.tinybox.Box` interface and TinyBus ABI v1
  exports, released as `libtinybox.so`
- CI: format, clippy, build, test, 90% line coverage in every file, rustdoc with
  `-D warnings`, an MSRV build, and a `cargo-deny` supply-chain check
- `PassthroughSandbox`: a sandbox that confines nothing and says so. It delegates
  to whatever `Host` it is given, so it is already generic over reach — pairing
  it with SSH in M4 needs no new code.
- `tinybox-host` with `LocalHost`, the only component that touches the OS
- `tinybox-cli`: `create`, `exec`, `ls`, `inspect`, `rm`, `snapshot`, `fork`, and
  a one-shot `run`, over a JSON box store that survives between invocations
- `DockerSandbox`: the first backend that confines anything — kernel isolation,
  enforced CPU/memory/process limits, filesystem snapshots, and forking. It
  drives `docker` through its `Host` rather than a socket, so Docker-over-SSH
  arrives free in M4 (ADR 0004).
- `SshHost`: reach another machine, inheriting the user's SSH config, keys, and
  agent. Docker-over-SSH needed **no Docker-side code**, as ADR 0004 predicted —
  `crates/tinybox-ssh/tests/composition.rs` is the receipt.
- `tinybox-sync`: blake3 fingerprinting and tar-over-stdin transfer, so a
  repeated sync with no edits sends nothing.
- Published ports on the spec, and `stdin` on `ExecRequest`.
- Named templates, so provisioning happens once rather than on every create.
- Box expiry with `tinybox reap`, and an injectable `Clock` so it is testable.
- Exclusions read from a workspace's own `.gitignore` and `.boxignore`.
- A real advisory lock on the box store, closing the lost-record race carried
  since M2.
- `NamespaceSandbox`: rootless kernel isolation with no daemon and no root,
  built on bubblewrap. **No `unsafe` was needed** — ADR 0005 records why ADR
  0003's expectation was wrong.

## Next
- **M7** — `MicroVmSandbox`: Firecracker, a vsock guest agent, and memory
  snapshots. The `Sandbox` trait is shaped to accommodate it.

## Deferred

- **A warm pool, and an autosnapshot cadence.** Both need a long-running process
  to keep the pool full and the timer running, and tinybox has none. `reap` is
  an explicit command for the same reason. The prerequisite is a daemon, which
  is its own decision rather than a detail of either feature.
- **Forwarding a remote box's port back to the local machine.** Needs `ssh -L`,
  a long-running process with a lifetime that `Host::run`'s run-to-completion
  shape cannot express. Publishing a port at creation, which backends *can*
  honor, shipped in M4.
- **Per-file delta sync.** Needs rsync's rolling checksum or an agent on the far
  side to negotiate with. The skip-when-unchanged win shipped in M4 and is the
  one that matters for an edit-run loop.
- **Nested `.gitignore` files.** Only the workspace root is read; see the spec
  for why a nested rule set and a tree fingerprint interact badly.

- **A seccomp allowlist and landlock for the namespace backend.** Both were in
  the original M6 plan and neither shipped. `bwrap --seccomp` takes a compiled
  BPF program this backend does not build, and landlock is not reachable
  through `bwrap` at all.
- **A persistent namespace sandbox.** Each command is a fresh `bwrap`, so
  writes outside the workspace do not survive between commands — which is why
  no snapshot or fork support is declared. Holding one open needs a supervised
  process, the same prerequisite as the warm pool.
- **Guest-side EROFS/VMDK rootfs.** microsandbox measured a 47× geomean here,
  but the gain came from deleting a host FUSE boundary that Docker and
  namespaces backends do not have. Relevant only under a microVM.
- **UFFD on-demand paging and access-order prefetch.** VMM restore techniques,
  meaningless before a hypervisor backend exists.
- **Host-side `smoltcp` stack with egress credential substitution.** High
  effort; TinyBus's `secret::Secret` covers the near-term need.

## Out Of Scope

- scheduling or placement across a fleet — tinybox runs a box where it is told
- anything that cannot be tested deterministically
- convenience wrappers that hide the capability contract from callers; a
  backend that cannot do something must say so, not approximate it
