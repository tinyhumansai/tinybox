# Native shell execution implementation order

[Specification](../specs/native-shell-execution.md).

1. Reproduce the absent module consumer through the unconditional real-artifact
   test in crates/tinybox-module/tests/grants_manifest_e2e.rs.
2. Add ShellExecRequest in crates/tinybox-bus/src/shell_execution.rs, append
   StartNativeShellExec and contract 1.14, and add TimedOut output failure.
3. Extend the existing collectors in tinybox-host/src/limited/{mod,jailed}.rs
   with observed standard-command bridges; retain owned kill/reap behavior.
4. Implement validation, environment and scratch ownership in the module's
   native_shell directory. Reuse native_jail preparation for strict confinement.
5. Integrate shell collectors and exact request identity in resources_stream.rs.
   Reuse existing reservations, output journals and resource cleanup.
6. Add behavioral tests beside each module and actual artifact execution.
   Validate formatting, affected/full tests, Clippy, build, coverage and
   cross-platform CI through the workflow runner.

Implementation is complete; upstream review and cross-platform CI remain. No host gitlink or availability claim is
part of this upstream slice.

## Rust toolchain environment

1. Seed child tests through Command.env to reproduce lost RUSTUP_HOME and
   CARGO_HOME bytes without changing the parent process environment.
2. Store environment values as OsString and include the two nonempty toolchain
   names. Preserve approved overrides, ordinary passthrough validation,
   Windows bootstrap, startup-hook removal and scratch ownership.
3. Verify the actual shell child sees exact OS bytes, empty homes are unset,
   approved overrides win and unrelated ambient names stay excluded.
4. Verify the same behavior through a compiled production-admitted module and
   Linux confinement using the grants from contract 1.20.

5. On macOS, verify byte-exact shell values for invalid UTF8 home names whose
   creation fails with EILSEQ, and require discovery to omit unavailable paths.
   Retain actual byte-named directories and confinement checks on Linux.
