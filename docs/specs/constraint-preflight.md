# Constraint preflight

`Sandbox::plan_check` inspects explicitly requested constraints without
allocating or starting a workload. `Sandbox::require` rejects the first
`Unsupported` **or** `BestEffort` declaration with a typed
`Error::ConstraintNotEnforced`. Unknown implementations report no constraints;
coarse lifecycle capabilities do not imply resource enforcement.

| Backend | Filesystem | Network denial | CPU | Memory | Pids | Disk | Subprocess denial |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Docker | Enforced | Enforced | Enforced | Enforced | Enforced | Unsupported | Unsupported |
| Namespaces | Enforced | Enforced | Enforced with cgroups | Enforced with cgroups | Enforced with cgroups | Unsupported | Unsupported |
| MicroVM | Enforced | Enforced | BestEffort | BestEffort | Unsupported | Unsupported | Unsupported |
| Landlock | Enforced when full filesystem ABI available | Unsupported | Unsupported | Unsupported | Unsupported | Unsupported | Unsupported |
| Seatbelt | BestEffort when present | BestEffort when present | Unsupported | Unsupported | Unsupported | Unsupported | BestEffort when present |
| Noop / unavailable platform | Unsupported | Unsupported | Unsupported | Unsupported | Unsupported | Unsupported | Unsupported |

Namespace resource support is opt-in; actual systemd/cgroup setup may fail and
must prevent execution. MicroVM vCPU counts round up and memory is rounded with
a minimum of one MiB, so arbitrary exact budgets cannot be promised. No backend
enforces the writable disk budget in `Resources`; consequently none declares
the coarse `ResourceLimits` capability. A caller requiring all resource fields,
including default disk, must expect refusal. This change does not implement new
OS resource controls.

Directory jails expose `JailBackend::plan_check` and `require` for filesystem
plus any requested network/subprocess denials. `spawn_required_with` and
`spawn_required` run the hard check before starting a child. Existing
`spawn_with(NoopBackend, ...)` is an explicit trusted passthrough; it is never
selected automatically. Legacy Seatbelt spawn remains available but its
filesystem declaration is best effort: it allows reads everywhere and writes
in `/private/tmp`. Strict preflight refuses it. Launcher presence does not prove the host enforces
profiles, so network and subprocess rules also remain best effort until an
enforcement probe can establish them. `isolation()` reports `None`: the
Seatbelt launcher is the mechanism used, not proof that the host actually
isolates the workload.

Landlock implements filesystem rules only (no network ABI rules or process
isolation). A filesystem-only strict jail may spawn, but
`is_suitable_for_untrusted_code` is false. Both direct and facade Landlock
spawns refuse network/subprocess denial flags rather than silently dropping
them. Windows AppContainer is not compiled; Windows has no enforced jail.

Preflight is a declaration check, not proof that runtime setup will succeed.
Backend spawn/create errors must propagate. Callers select hard constraints
explicitly before legacy lifecycle methods; those methods do not automatically
turn every field of a `BoxSpec` into a hard request.

## Registry path ownership

Registry bases are trusted host-owned directories and must not be writable by
jailed workloads. `open` canonicalizes the caller's trusted base once. Older
records sharing that exact lexical base are normalized only when their suffix
has normal components; traversal introduced in a record remains forbidden.
Older symlink aliases are resolved and checked against the canonical base.

Spawning requires an existing root, canonicalizes it before containment, and
passes that checked canonical root directly to the backend. It never accepts a
synthetic missing path or recanonicalizes an unchecked alias after the check.
Missing-path resolution retires already-missing entries or diagnoses an outside
missing path; a failed existing-root lookup always refuses spawning even when
the path appears during diagnosis. These path-based APIs do not promise descriptor-atomic protection
against a separate host process with write authority over the registry base
replacing existing directories during an operation. That authority must stay
with the host; untrusted processes get only their jail root and cannot replace
its parent entry. Descriptor-based hostile-host filesystem operations would
require a distinct backend contract rather than claiming atomicity here.
