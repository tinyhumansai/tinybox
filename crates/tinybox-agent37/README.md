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
| `src/transport.rs` | The `Transport` seam (4 calls) + `HttpTransport` (`reqwest`) — the only code touching the network or the key. |
| `src/sandbox/mod.rs` | `Agent37Sandbox: Sandbox` — create/exec/inspect/destroy over `Transport`, snapshot/fork refuse. |
| `*_tests.rs` | `config_tests`, `api_tests`, `sandbox/mod_tests` (fake `Transport`, `MemoryStore`). |

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
