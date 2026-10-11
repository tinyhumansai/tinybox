# Local grant discovery implementation sequence

[Specification](../specs/local-grants.md). This records the implementation order
and verification for the existing discovery slice.

1. Define LocalGrantConfig, ProtectedPaths, ResolveLocalGrantsRequest and
   LocalGrants in crates/tinybox-bus/src/grants.rs; append ResolveLocalGrants
   and contract 1.11 in src/lib.rs, with wire compatibility tests.
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
