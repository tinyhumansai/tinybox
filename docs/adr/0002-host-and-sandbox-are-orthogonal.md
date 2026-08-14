# 2. Host and sandbox are orthogonal

- **Status:** Accepted
- **Date:** 2026-08-14

## Context

tinybox must run code under Docker, over SSH, on the local machine, under Linux
namespaces, and eventually inside a microVM — and each of those must be usable
either for the runner (the agent driving the work) or for the workspace (where
the user's code executes).

The obvious shape is a single `Backend` trait with one implementation per
supported environment. It collapses under its own combinations. SSH and Docker
are not alternatives to each other: SSH says *which machine*, Docker says *what
confines the process*. Any caller wanting Docker on a remote machine forces a
`DockerOverSsh` variant, and the next axis added multiplies the set again —
`NamespacesOverSsh`, `MicroVmOverSsh`, and so on. Each is a distinct
implementation to write, test, and keep correct, despite containing no new
ideas.

The two questions also have different answers about trust. A host provides
reach and no confinement whatsoever. A sandbox provides confinement and says
nothing about where it runs. Merging them produces a type whose isolation
guarantee cannot be stated without also knowing its transport.

## Decision

Model reach and confinement as two independent traits, joined by a `Placement`
that pairs one of each.

- `Host` — names a machine and runs a command on it. `local`, `ssh`.
- `Sandbox` — owns box lifecycle, isolation, and snapshots. `passthrough`,
  `docker`, `namespace`, `microvm`.

`BoxSpec` carries two placements, `runner` and `workspace`, which need not
match.

Every `Sandbox` declares a `SandboxCapabilities`. Core checks the declaration
before dispatching and returns `Error::Unsupported`; a backend must never
emulate a capability it has not declared.

## Consequences

- Pairings cost nothing. `ssh` + `docker` works the day both exist, with no
  code naming that combination and no test matrix entry for it.
- Adding a host is `O(1)` in sandboxes and vice versa, so the two axes can grow
  independently.
- A local runner driving a remote workspace is expressible, which a single
  placement could not represent at all.
- Isolation strength is a property of the sandbox alone and can be stated
  without reference to transport — which is what makes
  `is_suitable_for_untrusted_code` a single honest predicate.
- The cost is one extra indirection: callers name two things where one would
  have done, and a provider registry must resolve both. For the common
  colocated case `BoxSpec::new` takes a single placement and applies it to
  both, so the cost falls only on callers that genuinely need the split.
- A backend that is genuinely both — a remote API that provisions and confines
  in one call — has to be modelled as a sandbox whose host is implicit. This is
  the one shape the split handles less naturally than a merged trait would.
