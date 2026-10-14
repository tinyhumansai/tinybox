# Native shell execution

Status: implemented upstream; review and cross-platform CI pending. Owner: TinyBox.
Sequence: [native shell plan](../plans/native-shell-execution.md).

Contract 1.14 appends StartNativeShellExec(ShellExecRequest) -> ProcessRef.
The caller supplies process/resource reservations, SelectShellRequest, optional
cwd, approved extra environment, stdin, native jail configuration, timeout
(default 30 seconds, positive, at most 24 hours), and approved existing absolute
state_dir. This is local passthrough execution only; other providers and
unavailable native jails refuse explicitly.

The module owns shell selection and raw Windows quoting, snapshots only the
standard execution passthrough, Windows bootstrap names and nonempty Rust
toolchain homes. It rejects empty ordinary passthrough values, applies approved
overrides, and finally removes
startup-hook variables. It clears the rest of the ambient environment.

Each execution owns a private scratch directory under
state_dir/artifacts/sandbox-scratch. TMPDIR, TEMP and TMP default to it unless
explicitly overridden. Approved state directory ACLs must be private on Windows;
the host owns approval of state_dir. Native jails add this module-created
scratch as a writable grant after validating caller grants and enforcement.
Filesystem preparation and recursive cleanup run on blocking workers so slow
storage does not stall the module runtime.

Capture uses owned pipes and the existing combined output budget, not shell
redirection. ReadOutput, Cancel, ReleaseOutput, Close and Shutdown retain their
cleanup barriers. Timeouts drop the waiter, wait for supervised kill/reap and
then publish TimedOut. Cleanup failures retain ownership and scratch for retry;
the pending timeout outcome survives until a later cleanup retry succeeds.
Scratch survives through journal retention and is reclaimed after acknowledged
release/close. Exact original request identity makes retry idempotent even if
the parent environment changed; mixing shell/argv reservations is refused.

Acceptance proves actual compiled-module execution on Windows and Unix,
quoting, environment isolation, scratch retention/cleanup, timeout/cancellation,
bounded output, identity replay, admission refusal and unavailable confinement.
OpenHuman host adaptation waits for an available released module.

## Rust toolchain environment

The native environment snapshots nonempty RUSTUP_HOME and CARGO_HOME as OS values, preserving Unix bytes. Approved UTF8 overrides retain precedence. Empty toolchain values behave as unset. Only these additional names are included; ordinary passthrough validation, Windows bootstrap, startup-hook removal and owned scratch remain unchanged. Canonical confinement grants are resolved separately using the current read-only host-state policy.
