# Local grant discovery

Status: implemented contract under review. Owner: TinyBox.
Sequence: [local-grants plan](../plans/local-grants.md).

Contract 1.11 appends ResolveLocalGrants(ResolveLocalGrantsRequest) -> LocalGrants.
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

The bus rejects non-UTF-8 targets and more than 64 input or final grants.
Missing/protected individual paths are omitted. Discovery is a snapshot; hosts
must prevent later protected entries or concurrent tree mutation. No kernel deny
rule for future credential filenames is claimed.

Acceptance: behavioral regressions cover every floor and include correction;
the actual dynamic artifact passes production manifest admission and discovery,
including explicit refusal of unsupported include expansions. No implementation
crate is needed by a host. Execution and host adapters remain separate work.
