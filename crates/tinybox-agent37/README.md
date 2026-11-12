# tinybox-agent37

A TinyBox sandbox backend over the **agent37** hosted HTTP sandbox API
(<https://www.agent37.com/docs/quickstart>), modeled on `tinybox-openshell`.
The structure, the `Sandbox` impl, the transport seam, the request/response
contract, and the tests are written against the real `tinybox-core` API and the
**real agent37 API**, and the crate compiles and its tests pass in the TinyBox
workspace (`cargo test -p tinybox-agent37`).

## Layout

| File | Purpose |
|---|---|
| `src/lib.rs` | Crate docs + exports (`Agent37Sandbox`, `Transport`, `HttpTransport`, `Agent37Config`, `NAME`, `DEFAULT_API_BASE`, `DEFAULT_SANDBOX_BASE`). |
| `src/config.rs` | `Agent37Config` + `ApiKey` (redacting `Debug`); reads `AGENT37_API_KEY` (required) and optional `AGENT37_API_BASE` / `AGENT37_SANDBOX_BASE` overrides. |
| `src/api.rs` | **Pure** request/response types + builders: `check_spec`, `create_body`, `instance_resources`, `exec_body` / `shell_command`, `exec_output`, `box_state_from_status`. |
| `src/transport.rs` | The `Transport` seam (5 calls) + `HttpTransport` (`reqwest`) — the only code touching the network or the key. Retries the exec refusals that prove the command never started (`409`, `503`). |
| `src/retention.rs` | **Pure** plan for a retained create: which listed instance to adopt, which expired ones to delete. |
| `src/sandbox/mod.rs` | `Agent37Sandbox: Sandbox` — create/exec/inspect/destroy over `Transport` (retained boxes adopted and expired on create, exec waits for a waking instance), snapshot/fork refuse. |
| `*_tests.rs` | `config_tests`, `api_tests`, `retention_tests`, `transport_tests` (an in-process HTTP stub, virtual time), `sandbox/mod_tests` (fake `Transport`, `MemoryStore`). |

## ADR 0004 deviation — the ADR-0008 exception

TinyBox ADR 0004 says a backend drives an external tool through its `Host`, so
credentials and transport stay out of TinyBox. agent37 is HTTP-native with no
CLI, so this backend owns an HTTP client and reads the key from config. That is
a **conscious, bounded deviation**, recorded in
[`docs/adr/0008-http-native-backends-own-their-transport.md`](../../docs/adr/0008-http-native-backends-own-their-transport.md):
an HTTP-native provider may own its client when it is confined behind the two
guarantees that ADR keeps —

1. the `Transport` trait is the only thing that touches the network, so the
   request builders and the `Sandbox` impl are pure and unit-tested without it;
2. the key enters only through config, is held in a redacting type, and is never
   logged — `reqwest` and the key never leave `transport.rs`.

## The agent37 HTTP contract

agent37 splits its API across two fixed hosts, so there is normally nothing to
configure but the key:

- **Control plane** — `https://api.agent37.com`, `Authorization: Bearer <key>`:
  - `POST   /v1/instances`        → create; body `CreateBody`; `201 { id, status, url }`
  - `GET    /v1/instances`        → list; `{ data: [ <instance> ] }`, newest first, no filters
  - `GET    /v1/instances/{id}`   → inspect; `{ id, status, … }`; 404 = gone
  - `DELETE /v1/instances/{id}`   → delete; 2xx or 404 = deleted
- **Exec** — `https://sandbox.agent37.app`, `X-Agent37-Key: <key>` header:
  - `POST   /v1/instances/{id}/exec` → exec; body `{ command }`; `{ exit_code, stdout, stderr, truncated }` (**plain** text, not base64)

Both bases are overridable (`AGENT37_API_BASE` / `AGENT37_SANDBOX_BASE`) for a
workspace custom domain or a local test stub.

Key mappings this backend makes, because agent37's model differs from TinyBox's:

- **Server-minted id.** agent37 returns the instance `id` on create; the backend
  records the box under that id (a valid `BoxId`) and addresses exec/inspect/
  delete with it directly — no client-derived name, no stored mapping.
- **Template, not image.** agent37 runs a *template name*, not a raw OCI image
  (inline image refs are rejected `400`). The host passes the agent37 template
  name in the `WorkspaceSource::OciImage` slot; a custom image is registered as
  a workspace template out of band first.
- **Single shell command.** agent37 exec takes one `command` run via `sh -c`, so
  `shell_command` composes the box's argv, cwd, env and stdin into one
  single-quoted line (stdin is base64-piped in).
- **Fixed resource shapes.** agent37 offers only `(2,4)`, `(4,8)`, `(4,16)`,
  `(4,32)` vCPU/GB; any other combination is a `400`. `instance_resources`
  **snaps** the spec's `cpu_millis`/`memory_bytes` up to the smallest covering
  shape (so the common 2 GiB default becomes `2 vCPU / 4 GB` instead of
  failing), capping at the largest; disk follows the shape. CPU/memory/disk are
  declared `BestEffort` (you get at least what you asked for, not exactly it).
  Filesystem and network are `Enforced` (kernel-isolated, created `deny-all`; a
  non-`Denied` spec is refused).

## Waking and readiness

A command is never sent to an instance that cannot take it yet:

- `Sandbox::exec` inspects the box first. `provisioning`, `starting` and
  `waking` map to `BoxState::Creating`, so it re-inspects with backoff (1, 2, 4,
  8, then 15 s steps; 60 s in all) before giving up with `InvalidState`.
  `sleeping` maps to `Ready`: exec itself wakes a sleeping instance.
- `HttpTransport::exec` retries `409` (a checkpoint is being written) and `503`
  (`try_again`, `wake_failed`, `wake_timeout`), up to six times at 0.5, 1, 2, 4,
  8 and 8 s. In both the command never started. It **never** retries `504`: the
  command keeps running behind it, and a retry would run it twice. Any other
  status, and any connection error, is reported at once.

## Retained boxes: sleep, find again, expire

A `BoxSpec` with `retention: Some(Retention { key, idle_sleep_secs,
delete_after_secs })` is one box per owner that outlives its handle:

- **Create body.** `auto_sleep: true`, `idle_timeout_seconds` clamped to
  300..=86400, and metadata `tinybox.key=<key>` beside `tinybox.namespace`.
  Without retention the body carries none of these.
- **Adopt.** A retained create first lists the workspace and, when an instance
  has `tinybox.key == key` and a usable status (running, sleeping, or still
  starting), records it locally under its own id and returns it instead of
  creating one. That is how a box is found again after a restart, since ids are
  minted by agent37 and the host's store may not survive. Several matches: the
  oldest by `created` wins. A failed store insert on an adopted box keeps the
  instance; the other failure paths delete what they just made, but an adopted
  box holds an owner's files.
- **Expire.** In the same pass, instances with a `tinybox.key` entry that are
  `sleeping` and whose `slept_at` is older than `now - delete_after_secs` are
  deleted (never the adopted one, at most 20 per pass, longest-asleep first; a
  failed delete is ignored). Instances without a `tinybox.key` entry are never
  touched: the workspace may be shared. Time comes from the sandbox's `Clock`.
- **Destroy.** `destroy` on a retained box removes only the local record and
  leaves the instance, so a host closing its handle on idle or at shutdown keeps
  the user's files. **A retained box ends only through the expiry pass.** A box
  created without retention is still deleted by `destroy`.
- **Listing failure.** A failed `list` fails the create rather than risking a
  second box for the same owner.
- **Other backends** refuse a spec with `retention` set
  (`Error::Unsupported { capability: Retention }`); only this one declares
  `Capability::Retention`. See `docs/specs/contract-2-4.md`.

Not run against the live service: the listing shape (`{ "data": [...] }`, no
pagination documented) and the metadata echo are taken from agent37's docs.

## Register it (TinyBox)

In `crates/tinybox-module/src/tinybus_module/mod.rs`, where `openshell` is added:

- push `"agent37"` into `exec_backends` and `create_backends`;
- add it to `registered_sandboxes()` with `tinybox_agent37::NAME` and
  `tinybox_agent37::Agent37Sandbox::declared_capabilities()`;
- update the `mod_tests.rs` assertions that pin the backend list.

`tinybox-agent37` is a dependency of `tinybox-module`; `make_sandbox` builds
`Agent37Sandbox::with_namespace(HttpTransport::from_env()?, store, namespace)`.

## Wire it up (OpenHuman, then chottu)

**OpenHuman** (`crates/openhuman-core/src/`), mirroring `openshell`:
`config/schema/security.rs` (`SandboxBackend::Agent37`), `sandbox/types.rs`,
`config/ops/sandbox.rs`, `doctor/checks/sandbox.rs`, `sandbox/mod.rs`
(`pub mod agent37;`), `sandbox/ops.rs` (three arms). See
`../../../../crates/openhuman-core/src/sandbox/agent37.rs` and the handoff
`wiring.md`. Bump the TinyBox gitlink after the TinyBox PR merges (bottom-up).

**chottu** (after the OpenHuman pin bump lands — see the handoff `context.md`):
`CHOTTU_SANDBOX_BACKEND=agent37` → `SandboxBackend::Agent37`; the key lives in
the host env (`AGENT37_API_KEY`), never in chottu config.

## Build / verify (in the TinyBox workspace)

```
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo build --all-targets --all-features
cargo test --all-features -p tinybox-agent37
```
