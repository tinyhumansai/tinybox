#!/usr/bin/env bash
# Make unprivileged bubblewrap usable on a GitHub Linux runner: install it and
# lift Ubuntu 24.04's AppArmor restriction on unprivileged user namespaces,
# which otherwise makes every bwrap jail fail (and its tests skip).
set -euo pipefail

if ! command -v bwrap >/dev/null 2>&1; then
    sudo apt-get update
    sudo apt-get install --yes bubblewrap
fi
if sysctl -n kernel.apparmor_restrict_unprivileged_userns >/dev/null 2>&1; then
    sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
fi
bwrap --version
