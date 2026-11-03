#!/usr/bin/env bash
# The workspace denies `unsafe_code`; only the Windows AppContainer FFI file may
# allow it, file-scoped. Any other code mention of the lint is a relaxation,
# whatever its spelling: `allow`, `expect`, `warn`, `cfg_attr(.., allow(..))`,
# a multi-line attribute, or a crate manifest override. Comment lines are prose.
# Every crate must inherit the workspace lints, or it has no unsafe_code lint.
set -euo pipefail

root="${1:-.}"
cd "$root"

allowed_file="crates/tinybox-jail/src/windows.rs"
allowed_line='#![allow(unsafe_code)]'

found="$(
  grep -RIn --include='*.rs' --include='Cargo.toml' -e 'unsafe_code' . \
    --exclude-dir=vendor --exclude-dir=target --exclude-dir=.git |
    grep -Ev '^[^:]+:[0-9]+:[[:space:]]*//' || true
)"
expected="./$allowed_file:"

violations="$(
  printf '%s\n' "$found" | grep -v '^$' | while IFS= read -r hit; do
    file="${hit%%:*}"
    text="${hit#*:}"
    text="${text#*:}"
    if [[ "$file" == ./Cargo.toml && "$text" =~ ^unsafe_code\ =\ \"deny\"$ ]]; then
      continue
    fi
    if [[ "$hit" == "$expected"* && "$text" == "$allowed_line" ]]; then
      continue
    fi
    printf '%s\n' "$hit"
  done
)"

if [[ -n "$violations" ]]; then
  printf 'unsafe_code may be relaxed only by `%s` in %s\nfound:\n%s\n' \
    "$allowed_line" "$allowed_file" "$violations" >&2
  exit 1
fi

if ! grep -Eq '^unsafe_code = "deny"$' Cargo.toml; then
  echo 'workspace unsafe_code lint must remain deny by default' >&2
  exit 1
fi

for manifest in crates/*/Cargo.toml; do
  if ! awk '/^\[lints\]$/ { getline; found = $0 == "workspace = true" } END { exit !found }' "$manifest"; then
    printf '%s must inherit the workspace lints: [lints] workspace = true\n' "$manifest" >&2
    exit 1
  fi
done

if [[ "$(grep -cxF "$allowed_line" "$allowed_file")" != 1 ]]; then
  echo 'Windows FFI exception must remain one file-scoped allowance' >&2
  exit 1
fi
