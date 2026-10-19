#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$root"
if [[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_OS:-}" == Linux ]]; then
  source scripts/ci/prepare-rootless-native-resources.sh
  export TINYBOX_REQUIRE_NATIVE_RESOURCE_TESTS=1
fi
.github/scripts/check-file-coverage.sh 90 coverage.json
