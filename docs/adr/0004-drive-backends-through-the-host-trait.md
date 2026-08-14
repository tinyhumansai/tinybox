# 4. Drive backends through the Host trait, not a native client

- **Status:** Accepted
- **Date:** 2026-08-14

## Context

The Docker backend has to talk to a daemon. There are two ways to do that.

The conventional one is a native API client — `bollard` speaks Docker's HTTP API
over a Unix socket. It is typed, it avoids parsing human-facing output, and it
is what most Rust projects reach for.

The other is to run the `docker` command, which tinybox already has a mechanism
for: [`Host`](../specs/tinybox-runtime.md) exists precisely to run a command
somewhere.

The choice is not obvious in isolation, but it is not in isolation. ADR 0002
made reach and confinement orthogonal so that `ssh` + `docker` would be Docker
on a remote machine at no cost. A socket client breaks that promise: a
`bollard` connection goes to a *local* socket, so the remote case would need
socket forwarding, a special-cased `DockerHost`, or a second implementation —
exactly the combinatorial explosion ADR 0002 was written to avoid.

The second consideration is testability. This workspace enforces 90% line
coverage in every file individually. A socket client is hard to exercise without
a daemon, which pushes real logic — which limits are applied, how a source
becomes an image reference, what a digest turns into — into code that only a
live integration test reaches.

## Decision

Backends that drive an external tool issue commands through their
[`Host`](../specs/tinybox-runtime.md), never through a native protocol client.

`DockerSandbox` holds an `Arc<dyn Host>` and runs `docker run`, `docker exec`,
`docker inspect`, `docker commit`, and `docker rm` through it.

Command construction is a separate module of pure functions
(`sandbox/args.rs`), so every decision it makes is a value that can be asserted
without running anything. Process execution stays in the thin layer above it.

Non-zero exits are distinguished by meaning rather than by mechanism: a failing
`docker` invocation becomes `Error::Backend` carrying Docker's own diagnostic,
because the operation did not happen; a failing command *inside* a box is
returned as an ordinary `ExecOutput`, because a command that runs and fails is a
result.

## Consequences

- **Docker over SSH is free.** When `SshHost` lands in M4, every Docker
  operation runs on the remote machine with no socket forwarding, no
  `DockerHost` special case, and no new code in this backend.
- **The dependency graph stays small.** `tinybox-docker` depends only on
  `tinybox-core` and `async-trait`. The released `cdylib` can include the Docker
  backend without also linking an HTTP stack — which is why the TinyBus module
  registers it at all.
- **Nearly everything is testable without a daemon.** 28 unit tests cover the
  whole backend against a scripted host; the live suite is reserved for what
  only a daemon can answer, such as whether the process table is really private.
- **The cost is real: the `docker` CLI is a human interface, not a contract.**
  Output format changes between versions, error text is unstable, and parsing is
  more fragile than a typed response. Three things keep that manageable —
  `--format` is used wherever Docker offers it, the parsing surface is small
  (one status word and one digest), and digest parsing validates rather than
  assumes, returning `Error::Backend` when the shape is wrong instead of
  producing a corrupt identifier.
- **A `docker` binary must be on the host's PATH.** A native client would only
  need the socket. This is the honest trade for the remote case working at all.
- If a backend ever needs something the CLI cannot express — streaming exec
  output incrementally is the likely first case — this decision is worth
  revisiting for that backend alone rather than reversing wholesale.

## Related

- ADR 0002 — host and sandbox are orthogonal, which is what this protects
