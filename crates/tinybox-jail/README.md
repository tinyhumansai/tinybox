# cwd_jail

Directory-jail facade. Given a declarative description of a workspace
(`Jail`), it spawns a child through an available sandbox backend. Linux
(Landlock) and macOS (Seatbelt) backends are compiled and selected by
`pick_backend()`. The Windows AppContainer backend is still not compiled (see
below). When no backend is usable the default backend is `unsupported`
(`is_available() == false`, `spawn` fails with `Unsupported`); callers can
explicitly select `NoopBackend` when unrestricted execution is intended.
It is a per-process complement to the box-level isolation in `tinybox-linux`:
the autonomy gate decides whether a command may run, and `cwd_jail` decides
what filesystem the approved child process sees. It jails the child it
spawns, never the core process itself.

## Responsibilities

- Describe a jail declaratively via a builder (`Jail::new(root, label)` plus
  `.add_read_only(...)`, `.add_read_write(...)`, `.deny_net()`,
  `.deny_subprocess()`). `add_read_write` grants an extra path outside the
  root the same access as the root (Landlock rule, Seatbelt `file-write*`
  subpath, `AppContainer` ACL), for host-owned scratch such as a per-call
  output-capture directory that must not land inside the root.
- Cache the default backend: Landlock on Linux kernels that support it,
  Seatbelt on macOS, otherwise the `unsupported` backend.
- Spawn a `std::process::Command` inside the jail, canonicalizing `root`
  (and the read-only and read/write paths) first so backends never see `..` or symlink
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
| `crates/tinybox-jail/src/detect.rs` | `pick_backend()`: first available OS backend, else an unsupported backend that fails closed. |
| `crates/tinybox-jail/src/noop.rs` | `NoopBackend`: no enforcement, plain `Command::spawn`. Always available. |
| `crates/tinybox-jail/src/linux.rs` | Landlock backend (Linux only, `landlock` feature, on by default). Applies the ruleset to a dedicated spawn thread so no `unsafe` `pre_exec` is needed. |
| `crates/tinybox-jail/src/macos.rs` | Seatbelt backend via `sandbox-exec`. Compiled on every host so the profile renderer is unit-tested everywhere; selected only on macOS. |
| `crates/tinybox-jail/src/windows.rs` | AppContainer implementation; **not compiled**: it needs `unsafe` FFI the workspace forbids and cannot return a waitable `std::process::Child` yet. |
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
- macOS forwards only variables explicitly supplied with `Command::env` or
  `Command::envs`. The launcher clears the inherited environment because Rust
  exposes no getter for `Command::env_clear`; this prevents restoring parent
  credentials a caller deliberately removed. Supply required variables such
  as `PATH` explicitly. Linux preserves the original command environment.
- macOS stdio is inherited: the Seatbelt wrapper cannot re-apply the
  original command's `Stdio` config, so it uses `sandbox-exec` defaults
  (inherit). The profile re-allows writes under the canonicalized `root` and
  `/private/tmp`, plus the exact `/dev/null` device for shell redirection;
  it does not grant `/dev` generally. Callers must canonicalize the root
  first (the `spawn` facade does this automatically) or writes inside it may
  be denied (for example `/tmp` resolving to `/private/tmp`).
- Linux Landlock is applied to a short-lived dedicated thread that then
  spawns the command; the child inherits the thread's domain and
  `no_new_privs`, the caller's thread keeps its privileges. Read-only paths
  also get `Execute` so the child can run binaries found there.
- Linux baseline grants (see `SYSTEM_READ_PATHS`, `DEVICE_PATHS` in
  `linux.rs`): `/usr /bin /sbin /lib* /etc` read+execute and a few harmless
  `/dev` nodes read+write. Everything else is denied unless the `Jail` grants
  it: the rest of `$HOME`, `/proc`, `/sys` and `/tmp` included. Grant scratch
  space and toolchain caches with `add_read_write` / `add_read_only`.
- On a kernel without Landlock (or a build without the `landlock` feature)
  the backend reports unavailable and `spawn` returns `Unsupported`; it never
  runs the command unconfined. The availability probe checks basic support;
  spawning also rejects partially enforced rulesets with `Unsupported` before
  running the child, including older ABIs that cannot restrict truncation.
- Registry containment guard: both `delete` and `jail_for` (used by
  `spawn_in`/`spawn_in_with`) refuse to operate on a record whose
  canonicalized `dir` is not under the canonicalized `base`, defending
  against a corrupted index pointing at `/`.
- Free-form input is length-logged, not value-logged (labels and notes), to
  avoid leaking arbitrary text into logs.
