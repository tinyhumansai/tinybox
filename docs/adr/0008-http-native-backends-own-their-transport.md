# 8. HTTP-native backends own their transport, behind a seam

- **Status:** Accepted
- **Date:** 2026-11-04

## Context

[ADR 0004](0004-drive-backends-through-the-host-trait.md) decided that a backend
driving an external tool issues commands through its [`Host`](../specs/tinybox-runtime.md),
never a native protocol client. That kept reach and confinement orthogonal (a
local socket client would have broken "Docker over SSH is free", ADR 0002) and
kept command construction a pure, testable value.

The `agent37` backend does not fit the shape ADR 0004 reasons about. agent37 is
a hosted sandbox service reached over HTTPS: there is no `agent37` binary to run
through a `Host`, and the box does not run on any machine tinybox places with a
`Placement` — it runs in agent37's own infrastructure, addressed by an
instance id the service mints. The `Host` abstraction has nothing to drive here.
Both of ADR 0004's motivations also fall away for it:

- **Reach is not a tinybox concern for this backend.** There is no local versus
  remote machine to keep orthogonal; the service is always remote, always at the
  same two hosts. There is no `*OverSsh` combinatorial explosion to avoid,
  because agent37 is not composed with a `Host` at all.
- **The "CLI is a human interface" cost does not apply.** agent37's API is a
  stable, versioned, typed JSON contract (`/v1/instances`), not human-facing
  command output. Parsing it is a typed deserialization, not screen-scraping.

So the ADR 0004 mechanism cannot be used, and the reasons it exists do not bite.
What remains is the risk a native client introduced in the first place:
untestable logic behind a live dependency, and a credential and socket entering
a backend that the rest of tinybox keeps out.

## Decision

A backend for a service that is **HTTP-native and has no command-line tool** may
own its HTTP client directly, instead of driving a `Host`, provided the client
is confined behind a seam that preserves ADR 0004's two guarantees:

1. **A `Transport` trait is the only thing that touches the network.** The
   backend's request builders and its `Sandbox` impl are pure over that trait:
   they turn a `BoxSpec`/`ExecRequest` into request values and a response into a
   `BoxInfo`/`ExecOutput`, asserting every decision without a socket. A fake
   `Transport` exercises the whole backend; a live suite is reserved for what
   only the service can answer. This is the same split ADR 0004 gets from
   `sandbox/args.rs`, drawn one layer higher.
2. **The credential enters only through configuration, and is never logged.**
   The key is read from the environment at the transport boundary (one module),
   held in a type whose `Debug` redacts it, and sent only as an auth header. No
   other part of tinybox sees it.

`tinybox-agent37` is the first and, for now, only backend under this exception.
It reads `AGENT37_API_KEY` from the environment; agent37's hosts are fixed
(`api.agent37.com` for the control plane, `sandbox.agent37.app` for exec) and
overridable (`AGENT37_API_BASE` / `AGENT37_SANDBOX_BASE`) only for a custom
domain or a test stub. It declares `IsolationLevel::Kernel` and enforces
`NetworkPolicy::Denied` (refusing any wider policy rather than asserting an
egress guarantee it does not own), and snapshot and fork return
`Error::Unsupported` rather than emulating what agent37 does not offer — rule 1
is unchanged by this ADR.

## Consequences

- **The released `cdylib` now links an HTTP stack.** `reqwest` with `rustls`
  (no system OpenSSL) is pulled in by `tinybox-agent37`, and therefore by
  `tinybox-module`. ADR 0004 noted the Docker backend's independence from an
  HTTP stack as a benefit; that benefit is spent the moment any HTTP-native
  backend is registered. It is confined to this one crate: `tinybox-docker`,
  `tinybox-openshell` and the rest still link no client.
- **Testability is preserved, not traded.** The backend is unit-tested against a
  fake `Transport` (config, request/response mapping, the create→exec→destroy
  lifecycle, the id and cleanup paths), with a single hand-run `live_smoke`
  example reserved for the real service.
- **The exception is narrow and named.** It applies only to a service with no
  CLI and a typed HTTP contract, and only behind the two guarantees above. A
  backend that *does* have a CLI stays under ADR 0004; this is not a licence to
  reach for a native client when a `Host` would do.
- **Orthogonality is untouched for every other backend.** agent37 is simply not
  a `Placement` target, so ADR 0002 and ADR 0004 continue to hold wherever reach
  and confinement actually compose.

## Related

- ADR 0004 — drive backends through the `Host` trait, the rule this carves a
  single, bounded exception to.
- ADR 0002 — host and sandbox are orthogonal, which this leaves intact.
