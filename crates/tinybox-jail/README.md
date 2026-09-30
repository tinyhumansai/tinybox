# cwd_jail

Directory-jail facade. Given a declarative description of a workspace
(`Jail`), it spawns a child through an available sandbox backend. Platform
backends are currently disabled until they can satisfy the workspace safety
policy and enforce the declared jail contract. The default backend therefore
returns `Unsupported`; callers can explicitly select `NoopBackend` when
unrestricted execution is intended.
It is a per-process complement to the box-level isolation in `tinybox-linux`:
the autonomy gate decides whether a command may run, and `cwd_jail` decides
what filesystem the approved child process sees. It jails the child it
spawns, never the core process itself.

## Responsibilities

- Describe a jail declaratively via a builder (`Jail::new(root, label)` plus
  `.add_read_only(...)`, `.deny_net()`, `.deny_subprocess()`).
- Cache the default backend; currently this is an unsupported backend on every
  platform while OS implementations are being brought into compliance.
- Spawn a `std::process::Command` inside the jail, canonicalizing `root`
  (and read-only paths) first so backends never see `..` or symlink
  trickery.
- Provide a persistent registry to manage many jailed workspaces side by
  side, each with a stable id, label, directory, and metadata, indexed in a
  JSON file.
- Return an unsupported error when no OS-level sandbox is available. Select
  `NoopBackend` explicitly only when unrestricted execution is intended.

## Key files

| File | Role |
| --- | --- |
| `crates/tinybox-jail/src/lib.rs` | Module docstring plus the thin facade: `spawn` / `spawn_with` / `default_backend` (cached via `OnceLock`). Re-exports the public surface. |
| `crates/tinybox-jail/src/jail.rs` | Core types: the `Jail` description struct (builder plus `canonicalize`/`canonicalize_or_log`) and the `JailBackend` trait (`name`/`is_available`/`spawn`). |
| `crates/tinybox-jail/src/detect.rs` | `pick_backend()`: returns an unsupported backend until a compliant platform backend is available. |
| `crates/tinybox-jail/src/noop.rs` | `NoopBackend`: no enforcement, plain `Command::spawn`. Always available. |
| `crates/tinybox-jail/src/linux.rs` | Proposed Landlock implementation; currently not compiled or selected. |
| `crates/tinybox-jail/src/macos.rs` | Proposed Seatbelt implementation; currently not compiled or selected. |
| `crates/tinybox-jail/src/windows.rs` | Proposed AppContainer implementation; currently not compiled or selected. |
| `crates/tinybox-jail/src/registry.rs` | `JailRegistry` and `JailRecord`: multi-jail manager persisted to `index.json`, with atomic-rename writes and containment checks. |
| `crates/tinybox-jail/src/{lib,jail,noop,macos,windows,registry}_tests.rs` | Sibling test suites, each `#[path]`-included from its source file. |

## Public surface

Re-exported from `lib.rs`:

- `Jail`, `JailBackend`: the declarative jail description and the
  OS-enforcement trait.
- `NoopBackend`, `NOOP_BACKEND_NAME`: the unenforced backend for callers that
  explicitly choose it.
- `JailRecord`, `JailRegistry`: persisted multi-jail manager.

Free functions in `lib.rs`:

- `default_backend() -> Arc<dyn JailBackend>`: process-wide cached, lazily
  auto-detected backend.
- `spawn(jail: &Jail, cmd: Command) -> io::Result<Child>`: canonicalize and
  spawn under the default backend.
- `spawn_with(backend: &dyn JailBackend, jail: &Jail, cmd: Command) -> io::Result<Child>`:
  same, with an explicit backend (tests or a forced weaker backend).

`JailRegistry` methods: `open`, `base`, `create`, `get`, `list`,
`find_by_label`, `rename`, `set_notes`, `delete`, `clear`, `spawn_in`,
`spawn_in_with`.

## Persistence

`JailRegistry` is rooted at a base directory (for example `~/.openhuman/jails/`
or `<workspace>/jails/`). Each jail is a `<base>/<id>/` directory; metadata
for all jails lives in `<base>/index.json`.

- `JailRecord` fields: `id`, `label`, `dir`, `backend_at_create`,
  `created_at_unix`, `updated_at_unix`, optional `notes`.
- The on-disk index is the source of truth; in-memory state (`Index`, a
  `BTreeMap` for deterministic ordering) is rebuilt on every `open()`.
- Writes are atomic (write-temp then rename, with a direct-overwrite
  fallback if rename-over fails). Mutating ops roll back the in-memory
  change if persistence fails.
- Ids are generated as `j<ts_hex><counter_hex>` (not cryptographically
  random, used only as directory names), with a collision-retry loop on
  `create`.
- Concurrency is guarded by a `std::sync::Mutex`; multi-process access is an
  explicit non-goal (no OS file locking).

## Dependencies

This crate depends only on std and:

- `std::process` (`Command`/`Child`), `std::fs`, `std::sync`
  (`Mutex`/`OnceLock`/`Arc`), `std::time`.
- `serde` / `serde_json`: `JailRecord` and the index serialization
  (registry).
- `landlock` crate: Linux backend, gated on the `landlock` cargo
  feature.
- `windows-sys`: Windows AppContainer FFI (Security/Isolation, Threading,
  Memory APIs).
- macOS backend shells out to the system binary `/usr/bin/sandbox-exec`.

The Linux backend's docstring references `crate::security::landlock` as
conceptual prior art, but the implementation here is self-contained; it does
not import that module.

## Notes and gotchas

- Not RPC-facing, no agent tools, no event bus. There is no `schemas.rs`,
  `tools.rs`, or `bus.rs`; the module exposes no `openhuman.*` RPC methods,
  owns no agent tools, and publishes or subscribes to no `DomainEvent`s.
- Backends differ in what `allow_net` and `read_only` mean. Landlock does
  not gate network at all; macOS Seatbelt grants `allow default` (full
  network) and treats `read_only` as informational since reads are already
  allowed; Windows AppContainer is the only backend that honors `read_only`
  as a real read grant and maps `allow_net` to the strictly outbound-only
  `internetClient` capability (LAN and inbound capabilities are deliberately
  excluded).
- Windows `spawn` currently returns an error after a successful launch.
  `spawn_in_container` creates the process successfully but cannot bridge
  the raw `HANDLE` into a `std::process::Child` (the needed
  `FromRawHandle for Child` is unstable), so it closes the handle and
  returns `io::ErrorKind::Unsupported`. See the TODO in `windows.rs`. The
  Windows path is compile-checked but flagged as needing real-hardware
  testing.
- macOS stdio is inherited: the Seatbelt wrapper cannot re-apply the
  original command's `Stdio` config, so it uses `sandbox-exec` defaults
  (inherit). The profile re-allows writes under the canonicalized `root` and
  `/private/tmp`, plus the exact `/dev/null` device for shell redirection;
  it does not grant `/dev` generally. Callers must canonicalize the root
  first (the `spawn` facade does this automatically) or writes inside it may
  be denied (for example `/tmp` resolving to `/private/tmp`).
- Linux Landlock runs in `pre_exec` (child-side, after fork), so the parent
  keeps its privileges; read-only paths also get `Execute` so the child can
  run binaries found there (for example `/usr/bin/sh`).
- Registry containment guard: both `delete` and `jail_for` (used by
  `spawn_in`/`spawn_in_with`) refuse to operate on a record whose
  canonicalized `dir` is not under the canonicalized `base`, defending
  against a corrupted index pointing at `/`.
- Free-form input is length-logged, not value-logged (labels and notes), to
  avoid leaking arbitrary text into logs.
