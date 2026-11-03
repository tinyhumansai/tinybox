# 3. Split the crate into a workspace to contain `unsafe`

- **Status:** Accepted, amended by [ADR 0005](0005-namespaces-through-bubblewrap.md)
- **Date:** 2026-08-14

> **Amendment.** Modern Ubuntu blocks unprivileged user namespaces for
> unconfined binaries, so the namespace backend drives `bwrap` instead of
> calling `clone` directly. The Windows AppContainer backend now has one
> narrowly scoped FFI exception at
> `crates/tinybox-jail/src/windows.rs`; the workspace default remains
> `unsafe_code = "deny"`, and CI rejects allowances in every other Rust source
> file. The rest of this decision — the split itself, and why — stands.

## Context

`Cargo.toml` sets the workspace default to `unsafe_code = "deny"`. The Windows
AppContainer APIs require a small Win32 FFI boundary; keeping the exception in
one file makes that boundary reviewable without relaxing the lint for the rest
of the workspace.

A rootless namespaces backend cannot honor that. It needs `clone` with
namespace flags, `unshare`, `pivot_root`, `mount`, and a seccomp filter loaded
at a precise moment between `fork` and `exec`. Safe wrapper crates cover much
of this, but not the post-`clone` child setup, where the code must be
async-signal-safe and no safe abstraction exists.

Three options were available:

1. Relax `unsafe_code` to `deny` crate-wide and allow unsafe throughout the
   platform backend.
2. Stay on `forbid` and shell out to a helper binary for the unsafe parts.
3. Keep the workspace default at `deny` and permit unsafe in one audited
   Windows FFI file, checked by CI.

Option 1 spreads the exception across a platform backend and makes the boundary
harder to audit.
Option 2 keeps the guarantee but pays a process spawn on every box creation and
moves the hard part into an unversioned binary that is harder to test than a
library.

The split has a second, independent motivation. The released artifact is a
`cdylib` loaded into a TinyBus host, and every dependency it links is
dependency the host inherits. A single crate would put `bollard` and `russh` —
an HTTP stack and an SSH implementation — into that graph whether or not the
deployment uses Docker or SSH.

## Decision

Convert the repository to a Cargo workspace. Hoist the lint configuration into
`[workspace.lints]` so every member inherits identical settings. Keep
`unsafe_code = "deny"` as the default and allow it only in
`crates/tinybox-jail/src/windows.rs`; the CI boundary check rejects allowances
in other production Rust files. The Windows FFI stays in that module, with each
invariant documented at the relevant call.

```text
crates/
├── tinybox-core/     # model and traits; unsafe FORBIDDEN
├── tinybox-host/     # LocalHost, SshHost
├── tinybox-docker/   # DockerSandbox
├── tinybox-linux/    # NamespaceSandbox; safe bubblewrap launcher
├── tinybox-cli/      # bin `tinybox`
└── tinybox-module/   # cdylib, TinyBus ABI v1
```

Members are created when they have real content, not up front.

## Consequences

- `unsafe` is auditable by directory. Reviewing it means reading one crate, and
  a diff that introduces `unsafe` anywhere else fails to compile rather than
  needing a reviewer to notice.
- The cdylib links only what it uses. Backends are separate crates, so a host
  that never wants SSH never links an SSH implementation.
- The model is testable without any backend, and `tinybox-core` reached 100%
  line coverage with no process, container, or syscall in the test path.
- Three CI files assumed a single package and had to change with this split:
  `check-file-coverage.sh` scanned `src/` and would have silently measured
  nothing; the MSRV job read `packages[0].rust_version`, which is arbitrary in
  a workspace; and `release.yml` derived the artifact name by transliterating
  the package name. The last now reads the cdylib target name from
  `cargo metadata`, so `[lib] name` and the package name can differ — which is
  what keeps the released file `libtinybox.so`.
- The ongoing cost is real: more manifests, and cross-crate changes touch more
  files. Path dependencies and `[workspace.dependencies]` keep version drift
  from being one of those costs.
- `vendor/tinybus` is its own workspace and must be listed in the root
  `exclude`. Without it cargo attaches the vendored crates to this workspace and
  their `serde.workspace = true` fails to resolve against a root that never
  declared serde.
