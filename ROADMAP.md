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

## Next

- **M2** — `LocalHost` and the passthrough sandbox: exec with streamed output,
  file operations, and the `tinybox` CLI. The first end-to-end box.
- **M3** — `DockerSandbox` and OCI image sources, with snapshots via commit.
- **M4** — `SshHost`, blake3 fingerprint sync that skips unchanged trees, and
  port forwarding. Composes with M3 at no cost.
- **M5** — content-addressed snapshots, `.boxignore` derived from `.gitignore`,
  fork, named templates, the TTL reaper, autosnapshot cadence, and a warm pool.
- **M6** — `NamespaceSandbox`: rootless user namespaces, cgroup v2, overlayfs,
  seccomp, and landlock, confined to `tinybox-linux`.

## Deferred

- **M7 — `MicroVmSandbox`.** Firecracker, vsock guest agent, and memory
  snapshots. The `Sandbox` trait is shaped to accommodate it; nothing is built.
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
