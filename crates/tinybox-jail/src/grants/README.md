# Local grant discovery

resolve_local_jail_grants returns canonical existing JailGrants through the
workspace Result type. ResolveLocalGrants exposes the same behavior through
the module, with UTF-8 paths and an input/final 64-grant limit.

mod.rs orchestrates discovery and read-only precedence; types.rs holds results.
floor.rs matches components, adjacent pairs, protected prefixes and credential
roots, preserving requested and canonical aliases and ancestor boundaries.
inspection.rs scans directory descendants without following links. Errors,
over 1,000,000 entries or over 128 levels refuse a grant. Pair-prefix symlinks
are refused conservatively. Discovery is a snapshot, not a kernel filename
deny rule for entries created later; hosts must control tree mutation.

git_config.rs reads admitted Git configs only. Relative includes retain their
logical parent, and visited identity combines canonical file and resolved parent.
Each link location remains read-only even when targets repeat. Includes stop at
depth eight. Quotes, supported Git escapes and unquoted comments are parsed.
Empty XDG_CONFIG_HOME is treated as unset. User-name and installation-prefix
include expansion cannot be resolved portably from the supplied contract:
~user/ and %(prefix)/ therefore reject the whole request explicitly, without
returning a partial grant set.

Automatic toolchains, Cargo executable/configuration state, shared dependency
caches and Git configuration are fixed read-only. A Cargo or Rustup home moved
with `CARGO_HOME` or `RUSTUP_HOME` (absolute and non-empty in the host's
environment) gets the same treatment as `~/.cargo` and `~/.rustup`. Writable extras cannot
promote them or their ancestors/descendants. Manual grants retain writable
precedence when they do not reach fixed state. Only allow_proc grants /proc,
read-only. Mutable tools need separately approved disposable state.

Hosts supply the complete protected floor and keep authorization. This module
does not start commands or weaken unavailable confinement. See
[the contract specification](../../../../docs/specs/local-grants.md).
