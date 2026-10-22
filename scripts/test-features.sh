#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
# macOS does not ship setsid; the Docker supervisor fixtures need its real
# process-session semantics even though they run without a Docker daemon.
case "${RUNNER_OS:-$(uname -s)}" in
  macOS|Darwin)
    brew install util-linux
    export PATH="$(brew --prefix util-linux)/bin:$PATH"
    ;;
  Windows|MINGW*|MSYS*|CYGWIN*)
    # Native Rust commands resolve /bin/sh at the current drive root, while
    # Git Bash resolves it inside its installation. Supply that same shell.
    pwsh -NoProfile -File scripts/test-windows-fixtures.ps1
    pwsh -NoProfile -File scripts/prepare-windows-fixtures.ps1 -PosixBin "$(cygpath -w /usr/bin)"
    export PATH="/usr/bin:$PATH"
    ;;
esac
case "${RUNNER_OS:-$(uname -s)}" in
  Linux)
    # The bubblewrap jail backend needs `bwrap` and unprivileged user
    # namespaces. Install them where we can and make a missing sandbox a test
    # failure (TINYBOX_REQUIRE_BWRAP=1) so the real isolation tests can never
    # pass by skipping.
    sudo_cmd=""
    if [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1; then sudo_cmd="sudo"; fi
    if ! command -v bwrap >/dev/null 2>&1 && command -v apt-get >/dev/null 2>&1; then
      $sudo_cmd apt-get update -qq
      $sudo_cmd apt-get install -y -qq bubblewrap
    fi
    # Ubuntu 24.04 blocks unprivileged user namespaces for unprofiled binaries.
    $sudo_cmd sysctl -w kernel.apparmor_restrict_unprivileged_userns=0 2>/dev/null || true
    export TINYBOX_REQUIRE_BWRAP=1
    bwrap --version
    log="$(mktemp)"
    cargo test --locked -p tinybox-jail --test bwrap_isolation --test bwrap_fd_leak -- --nocapture --test-threads=1 2>&1 | tee "$log"
    ran="$(grep -c '\[bwrap-real\] .* ok in ' "$log" || true)"
    echo "bwrap real isolation tests that ran: $ran"
    if [ "$ran" -lt 22 ]; then
      echo "expected at least 22 real bwrap tests to run, saw $ran" >&2
      exit 1
    fi
    ;;
esac
python3 scripts/test-e2e-version.py
cargo test --locked --workspace
cargo test --locked --workspace --all-features
python3 scripts/check-library-engines.py
case "${RUNNER_OS:-$(uname -s)}" in
  Windows|MINGW*|MSYS*|CYGWIN*) ;;
  *)
    python3 scripts/test-feature-environment.py
    python3 scripts/test-package-layout.py
    ;;
esac
