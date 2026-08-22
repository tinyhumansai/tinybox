# 7. Reach includes forwarding, and detachment is one shell mechanism

- **Status:** Accepted
- **Date:** 2026-08-22

## Context

Both traits were shaped around one workload: run a command, wait, collect what
it produced. That is the right shape for a build, a test run, or an agent's
command, and it is the wrong shape for a *service*.

Putting a server in a box needs two things tinybox could not express.

**Nothing could outlive its own command.** `Sandbox::exec` returns an
`ExecOutput`, which means it waits. Starting `openhuman-core serve` through it
never returns, and there is no other way in.

**A published port was not necessarily reachable.** `PortMapping` publishes a
guest port to *its host's* address space, which is exactly right — and when the
host is another machine, the caller who asked for it still has no route to it.
No amount of sandbox-side configuration changes that, because the gap is not in
the confinement, it is in the reach.

The second one is the more interesting mistake, because it was invisible. Every
piece worked: `ssh` + `docker` composed as ADR 0002 promised, `--publish` was
applied, `inspect` reported the mapping. The port was simply on the wrong
machine, and nothing in the model said so.

## Decision

**Forwarding is a `Host` operation.** `Host::forward(SocketAddr) -> Forward`
answers "make that address reachable from here". `LocalHost` hands the address
back; `SshHost` holds an `ssh -N -L` child. The returned `Forward` is a guard:
the path exists for exactly as long as the value does.

**Detachment is one mechanism in core, not one per backend.**
`Sandbox::{spawn, is_running, stop}` are declared alongside
`Capability::Detach`, and every implementation dispatches through
`tinybox_core::detach`, which builds a shell command that backgrounds the
command and records its pid in a file named after a tinybox-minted `ProcessId`.

Both trait methods default to `Error::Unsupported`, so a backend opts in.

## Consequences

- **`ssh` + `docker` now reaches all the way.** A container on another machine
  publishes to that machine, and the forward closes the remaining gap — with no
  code naming that pairing, which is the same property ADR 0002 bought for
  command dispatch, extended to connections.
- **The detach mechanism is deliberately *not* `docker exec --detach`.** That
  flag exists and would have been the obvious choice for the Docker backend
  alone. It hands back nothing a caller could name, so there would be no way to
  ask whether the process is still running or to stop it — and `ssh` and the
  local host have no equivalent flag at all. The shell is the one thing every
  box that can host a server already has, so it is the one mechanism.
- **A backend declaring `Detach` promises more than "it ran".** It promises the
  pid file survives to the next command and the process keeps running between
  commands. `namespace` and `microvm` therefore decline: the first re-binds its
  directory per command, the second returns only what the command printed. A
  background process that cannot be found or stopped is worse than a refusal,
  because it looks like it worked.
- **Shell quoting moved into core and became public** (`tinybox_core::shell`).
  It was `tinybox-ssh`'s private module, written where the no-injection property
  had to be re-established by hand. Detachment is the second such place, and a
  second copy of a command-injection-critical function is a second chance to get
  it wrong.
- **`SshHost::forward` refuses when its inner host is not local.** Every other
  operation on that type composes freely, because it builds a command line and
  lets the inner host decide where it runs. A tunnel cannot: it is a process
  that has to keep running, which `Host::run` cannot express, so a chained host
  would open it on the wrong machine and report an address leading nowhere.
  `ProxyJump` in the user's SSH config does that case properly and needs no code
  here.
- **The pid file is a real cost.** It lives in `/tmp` inside the box, so a box
  whose `/tmp` is read-only or non-POSIX cannot detach, and a `ProcessId`
  outlives the process it names until `stop` removes the file. `stop` therefore
  removes it unconditionally — a stale file would make a later probe answer
  about whatever process inherits that pid next.
- **`forward` blocks in the CLI.** There is no daemon to hand a guard to and no
  honest way to record a tunnel this process is no longer holding open, so
  `tinybox forward` running *is* the forward existing. On a local host, where
  nothing is held open, it prints the address and returns rather than pretending.

## Related

- ADR 0002 — host and sandbox are orthogonal; this extends that split from
  command dispatch to connections
- ADR 0004 — backends drive external tools through `Host`, which is why `ssh -L`
  is a command line here too
