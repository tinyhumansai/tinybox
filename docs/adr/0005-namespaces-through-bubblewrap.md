# 5. Build the namespace sandbox on bubblewrap, not raw syscalls

- **Status:** Accepted
- **Date:** 2026-08-14
- **Amends:** [ADR 0003](0003-workspace-split-to-contain-unsafe.md)

## Context

ADR 0003 split this repository into a workspace so that `unsafe` could be
confined to one crate. Its reasoning was specific: a rootless namespace backend
needs `clone` with namespace flags, `unshare`, `pivot_root`, `mount`, and a
seccomp filter loaded between `fork` and `exec`, and no safe wrapper exists for
the post-`clone` child setup. `tinybox-linux` was reserved as the one place the
lint could be relaxed.

Building it revealed that the premise no longer holds, for a reason that has
nothing to do with taste.

**Modern Ubuntu blocks the syscall outright.** This machine reports:

```text
kernel.apparmor_restrict_unprivileged_userns = 1
```

With that set, an unconfined binary calling `clone(CLONE_NEWUSER)` is refused by
AppArmor regardless of `kernel.unprivileged_userns_clone` or `/etc/subuid`. It
is not a permissions problem tinybox could ask the user to fix with a sysctl;
it is the distribution's default posture, shipped since Ubuntu 23.10 and now
carried by the most common Linux server and desktop distribution.

Confirming it directly:

```text
$ unshare --user --map-root-user --pid --fork true
unshare: write failed /proc/self/uid_map: Operation not permitted

$ bwrap --unshare-user --unshare-pid --proc /proc ... -- /bin/sh -c 'id -u'
1000
```

`bwrap` works because Ubuntu ships an AppArmor profile permitting exactly this
program to create user namespaces. A hand-written backend would have to ship and
install a profile of its own — a privileged, distribution-specific installation
step for a tool whose entire premise is that it needs no privilege.

The second consideration is one ADR 0003 raised itself and then set aside:
getting namespace setup right is where sandbox CVEs live. Mount propagation,
`/proc` masking, the order of `pivot_root` against `umount`, and
async-signal-safety in the child are each capable of producing a sandbox that
looks isolated and is not. Bubblewrap is a mature, widely deployed
implementation of precisely that sequence — it is what Flatpak confines
applications with.

## Decision

`tinybox-linux` drives `bwrap` through its [`Host`](0004-drive-backends-through-the-host-trait.md),
exactly as the Docker backend drives `docker`.

`unsafe` is **not** enabled anywhere. `unsafe_code = "forbid"` stays in
`[workspace.lints]` with no exception, and the reservation ADR 0003 made for
this crate is withdrawn.

Rootless cgroup v2 limits go through `systemd-run --user --scope`, which is the
only route an unprivileged process has to a delegated cgroup. They are opt-in on
the backend, because a machine without a systemd user session cannot provide
them, and a sandbox that accepted a memory cap it could not apply would be
claiming something untrue.

## Consequences

- **The workspace has no `unsafe` at all.** A stronger outcome than ADR 0003
  planned for, and the split it introduced still earns its keep — dependencies
  stay out of the released `cdylib`, and backends remain independently
  testable.
- **It works on the distribution most people actually run.** A raw-syscall
  backend would fail on default Ubuntu, which is the worst possible failure
  mode for a security boundary: unavailable exactly where it is most needed.
- **The whole boundary is a value a test can assert on.** Which namespaces are
  unshared, what is bound read-only, what is bound writable, whether the
  environment is cleared — all of it is a command line built by a pure
  function, so 21 unit tests cover it without a kernel, and the live suite
  checks the boundary actually holds.
- **`bwrap` must be installed.** A real new dependency on the host, the same
  trade ADR 0004 made for `docker`. It is packaged everywhere as
  `bubblewrap`.
- **Some control is given up.** A seccomp allowlist is expressible through
  `bwrap --seccomp` but needs a compiled BPF program, which this backend does
  not yet build; landlock is not reachable through `bwrap` at all. Both were
  named in the original M6 plan and neither ships. They are recorded as
  deferred rather than quietly dropped.
- **If bubblewrap ever becomes the constraint** — a filter it cannot express, a
  platform it does not target — this decision is worth revisiting for that
  capability alone. Reversing it means reinstating the `unsafe` allowance ADR
  0003 described, and shipping an AppArmor profile besides.

## Related

- ADR 0003 — the workspace split, whose `unsafe` reservation this withdraws
- ADR 0004 — driving backends through the `Host` trait, which this follows
