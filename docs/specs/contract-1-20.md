# Contract 1.20: native jail read denials

Part of tinyhumansai/openhuman#7819.

Contract 1.20 is a vocabulary bump. It appends no bus member, so `METHODS` is
unchanged. A host that sends a non-empty `deny_read` requires a module minor of
at least 20, which `tinybox_bus::is_compatible` already enforces.

## Added

- `NativeJailConfig::deny_read: Vec<String>`: absolute paths the child may
  neither read nor write, even inside the root or a grant. Serde default empty
  and omitted when empty, so 1.19 requests decode unchanged.
- `JailBackend::carves_denials()`, default `false`: whether a backend can
  subtract a denial from a grant.

## Semantics

- Validated like grants (absolute, no `..`, no NUL, bounded length, counted
  against `MAX_NATIVE_JAIL_GRANTS`). Missing paths are retained so a store
  created after preflight remains denied. Existing aliases and missing paths
  beneath existing symlinks resolve to canonical targets; denials are resolved
  and checked again immediately before spawn.
- Refused (`INVALID_FILE_PATH`) when a denial is the root, an ancestor of it, or
  covers a writable grant: the command would have no workspace.
- Refused as unavailable when a denial overlaps an explicit or implicit grant
  and the backend cannot carve it out. Landlock's system and device baseline
  paths are implicit grants; the backend reports them so native preflight can
  reject credential denials that would otherwise be overridden. Outside every
  grant, allow-list backends already deny the path.
- Allow-list backends recheck canonicalized denials at spawn and refuse if a
  path created or redirected after preflight now overlaps the root, a grant,
  or an implicit baseline path. Direct Landlock backend callers receive the
  same check.
- A backend that carves denials may deny a nested path inside a writable grant;
  it still refuses a denial equal to or containing that grant.
- Seatbelt reads are allow-default, so the profile ends with
  `(deny file-read* file-write* (subpath ...))`, after the write allows it
  overrides. `subpath` matches a single file as well as a tree.

The host chooses the paths (its credential-store floor); the module only
enforces them.
