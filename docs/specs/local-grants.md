# Local grant discovery

Status: implemented contract under review. Owner: TinyBox.
Sequence: [local-grants plan](../plans/local-grants.md).

Contract 1.9 appends ResolveLocalGrants(ResolveLocalGrantsRequest) -> LocalGrants.
The caller supplies operator home, LocalGrantConfig and ProtectedPaths.
The host owns authorization and the unconditional floor; discovery starts no
process and makes no approval decision.

Existing extras expand ~/ against the supplied home and canonicalize.
Requested and canonical names must clear component, adjacent-pair, prefix and
credential-root exclusions. Protected prefixes and credential roots also
exclude recursive ancestors, retaining raw, parent-resolved and target aliases.
Directory descendants are inspected at discovery time; IO errors and traversal
bounds (1,000,000 entries, 128 levels) omit the grant. Nested links are not
followed; protected pair-prefix aliases are conservatively refused.

Toolchain discovery includes existing system roots, operator Rustup/NVM/npm,
piecewise Cargo and admitted Git config/ignore paths. Fixed host executable,
configuration and cached dependency state remain read-only; writable extras
cannot promote it. Mutable toolchains require disposable approved state.
Only the explicit allow_proc toggle grants /proc, read-only.

Git include discovery keeps logical relative resolution and protects all link
locations. The visited key includes canonical file and logical parent, with
depth eight bounding cycles. Empty XDG_CONFIG_HOME is unset. Quoted markers,
supported escapes and unquoted comments preserve Git pathname semantics.
~user/ and %(prefix)/ expansions are unsupported: the complete request returns
UnsupportedOperation instead of incomplete grants.

The default bus request rejects non-UTF-8 targets. Contract 1.20 callers can
opt into raw Unix path grants. The combined grant limit remains 64.
Missing/protected individual paths are omitted. Discovery is a snapshot; hosts
must prevent later protected entries or concurrent tree mutation. No kernel deny
rule for future credential filenames is claimed.

Acceptance: behavioral regressions cover every floor and include correction;
the actual dynamic artifact passes production manifest admission and discovery,
including explicit refusal of unsupported include expansions. No implementation
crate is needed by a host. Execution and host adapters remain separate work.

## Custom Rust homes and Unix grant transport (contract 1.20)

Existing absolute nonempty RUSTUP_HOME and CARGO_HOME paths are discovered on the module machine as OS paths. Defaults remain admitted by current toolchain policy. Rustup and selected Cargo bin/config/env/registry/git entries are read-only; credential floors and fixed-state alias protections apply to every selected root. Missing or invalid configured roots are skipped; discovery creates no directories.

Callers opt into allow_unix_paths to receive non-UTF8 canonical Unix paths in an additive unix_paths grant group (raw byte vectors). UTF8 grants retain their established string representation. The same group can be supplied in native jail configuration after host approval. Empty optional groups preserve previous wire payloads. Module decoding rejects NUL, relative paths, parent traversal, oversized paths, unsupported platforms and combined grant counts above the established limit. Hosts require the new contract before sending byte grants and retain protected-path admission.
