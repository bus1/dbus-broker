#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: D-Bus Broker Developers

set -euo pipefail

args=(--mount --pid --mount-proc --fork --kill-child)
if (( EUID != 0 )); then
    args+=(--user --map-auto --map-root-user)
fi

# Capture diagnostics without writing test messages to the host journal.
exec unshare "${args[@]}" bash -s -- "$(dirname "$0")/test.py" <<'BASH'
set -eu
mount -t tmpfs tmpfs /run/systemd/journal
exec python3 "$1"
BASH
