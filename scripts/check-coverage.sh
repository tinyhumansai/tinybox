#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$root"
# The gate's line accounting depends on the compiler: the same tests over the
# same code count different lines as coverable, and as covered, under another
# rustc. So the gate runs on one pinned toolchain, and the pin is bumped on
# purpose, together with whatever the new numbers need, never by a stable
# release landing on the runner.
export RUSTUP_TOOLCHAIN=1.99.1
if [[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_OS:-}" == Linux ]]; then
  rustup toolchain install "$RUSTUP_TOOLCHAIN" --profile minimal --component llvm-tools
  source scripts/ci/prepare-rootless-native-resources.sh
  export TINYBOX_REQUIRE_NATIVE_RESOURCE_TESTS=1
fi
.github/scripts/check-file-coverage.sh 90 coverage.json
