# Local grant discovery implementation sequence

[Specification](../specs/local-grants.md). This records the implementation order
and verification for the existing discovery slice.

1. Define LocalGrantConfig, ProtectedPaths, ResolveLocalGrantsRequest and
   LocalGrants in crates/tinybox-bus/src/grants.rs; append ResolveLocalGrants
   and contract 1.9 in src/lib.rs, with wire compatibility tests.
2. Implement discovery in crates/tinybox-jail/src/grants/mod.rs and types.rs.
   Put alias/component boundaries in floor.rs, bounded subtree admission in
   inspection.rs and bounded quote-aware Git include discovery in git_config.rs.
3. Reproduce security and pathname defects before fixes in mod_tests.rs and
   git_config_tests.rs. Preserve manual writable precedence only outside fixed
   read-only state. Return the workspace Result for unsupported expansion.
4. Dispatch discovery from crates/tinybox-module/src/tinybus_module/mod.rs.
   Check input/final grant bounds and UTF-8 without exposing native paths.
5. Build the real cdylib unconditionally with --locked --offline in
   crates/tinybox-module/tests/grants_manifest_e2e.rs. Admit its full manifest
   and invoke successful discovery plus unsupported-expansion refusal.
6. Keep module README/public method table and this specification aligned.
   Run cargo fmt --all -- --check, cargo test --all-features,
   cargo clippy --all-targets --all-features -- -D warnings, and
   cargo build --all-targets --all-features through the workflow's long runner.

Discovery implementation is complete subject to review and recorded validation.
Execution, released-module consumption and OpenHuman adapters are subsequent
slices and are not represented as delivered by this prerequisite.

## Custom Rust homes and Unix grant transport (contract 1.20)

1. Reproduce custom UTF8 and Unix-byte Rust home discovery failures against
   untouched production using subprocess-seeded public API tests. Reproduce
   missing toolchain environment in an actual shell child the same way.
2. Discover configured absolute Rustup and Cargo homes as OS paths. Keep
   Rustup and selected Cargo state read-only, preserve credential floors and
   reserve aliases before admitting writable extras.
3. Snapshot nonempty RUSTUP_HOME and CARGO_HOME as OS values for native shell
   execution, with approved UTF8 overrides retaining precedence.
4. Add opt-in byte grant transport and strict canonical decoding. Cover default
   wire compatibility, malformed paths, combined bounds and approved flags.
5. Exercise the production-admitted dynamic module with UTF8 and Unix-byte
   homes, actual Cargo/Rust commands and Linux filesystem confinement.
   On macOS, assert the filesystem rejects invalid UTF8 names with EILSEQ and
   discovery omits those unavailable homes; preserve byte-exact shell values.
   On Unix filesystems accepting these names, assert actual byte-path grants.
6. Run all four canonical checks and the per-file coverage gate for the exact
   candidate. Publish the reviewed upstream contribution from Sayr.
7. Integrate OpenHuman after the accepted TinyBox module release is available.
