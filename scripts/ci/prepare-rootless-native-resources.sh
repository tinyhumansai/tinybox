#!/usr/bin/env bash
set -euo pipefail

sudo apt-get update
sudo apt-get install --yes bubblewrap dbus-user-session systemd

uid="$(id -u)"
sudo loginctl enable-linger "$USER"
sudo systemctl start "user@${uid}.service"
runtime_dir="/run/user/${uid}"
export XDG_RUNTIME_DIR="$runtime_dir"
export DBUS_SESSION_BUS_ADDRESS="unix:path=$runtime_dir/bus"
source "$(dirname "${BASH_SOURCE[0]}")/prepare-bwrap.sh"

systemctl --user show-environment >/dev/null
systemd-run --user --scope --quiet --property=CPUQuota=10% -- /bin/true
