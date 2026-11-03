#!/usr/bin/env bash
# Behavioral checks for check-windows-unsafe-boundary.sh: every spelling of a
# relaxation fails, prose and the one allowance pass.
set -euo pipefail

guard="$(cd "$(dirname "$0")" && pwd)/check-windows-unsafe-boundary.sh"
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
failures=0

tree() {
  local dir="$scratch/$1"
  mkdir -p "$dir/crates/tinybox-jail/src" "$dir/crates/other/src"
  printf '[workspace.lints.rust]\nunsafe_code = "deny"\n' > "$dir/Cargo.toml"
  printf '//! Windows.\n#![allow(unsafe_code)]\n' > "$dir/crates/tinybox-jail/src/windows.rs"
  printf '//! Mentions `unsafe_code` in prose only.\n' > "$dir/crates/other/src/lib.rs"
  printf '[package]\nname = "other"\n\n[lints]\nworkspace = true\n' > "$dir/crates/other/Cargo.toml"
  printf '%s' "$dir"
}

expect() {
  local want="$1" name="$2" dir="$3"
  if bash "$guard" "$dir" >/dev/null 2>&1; then got=pass; else got=fail; fi
  if [[ "$got" != "$want" ]]; then
    printf 'FAIL %s: expected %s, got %s\n' "$name" "$want" "$got" >&2
    failures=$((failures + 1))
  fi
}

expect pass baseline "$(tree baseline)"

for spelling in \
  '#![allow(unsafe_code)]' \
  '#[expect(unsafe_code)]' \
  '#![warn(unsafe_code)]' \
  '#[cfg_attr(windows, allow(unsafe_code))]' \
  '#[allow(clippy::all, unsafe_code)]'; do
  dir="$(tree "case$RANDOM$RANDOM")"
  printf '%s\nfn f() {}\n' "$spelling" >> "$dir/crates/other/src/lib.rs"
  expect fail "$spelling" "$dir"
done

dir="$(tree multiline)"
printf '#[cfg_attr(\n    windows,\n    allow(unsafe_code)\n)]\nfn f() {}\n' >> "$dir/crates/other/src/lib.rs"
expect fail multi-line-attribute "$dir"

dir="$(tree manifest)"
printf '[lints.rust]\nunsafe_code = "allow"\n' >> "$dir/crates/other/Cargo.toml"
expect fail crate-manifest-override "$dir"

dir="$(tree no-inheritance)"
printf '[package]\nname = "other"\n' > "$dir/crates/other/Cargo.toml"
expect fail crate-without-workspace-lints "$dir"

dir="$(tree workspace-allow)"
printf '[workspace.lints.rust]\nunsafe_code = "allow"\n' > "$dir/Cargo.toml"
expect fail workspace-relaxed "$dir"

dir="$(tree second-allow)"
printf '#[allow(unsafe_code)]\nfn g() {}\n' >> "$dir/crates/tinybox-jail/src/windows.rs"
expect fail item-scoped-allowance-in-windows "$dir"

dir="$(tree vendored)"
mkdir -p "$dir/vendor/x/src"
printf '#![allow(unsafe_code)]\n' > "$dir/vendor/x/src/lib.rs"
expect pass vendored-code-ignored "$dir"

if [[ "$failures" -ne 0 ]]; then
  exit 1
fi
echo 'unsafe boundary guard: all cases behave'
