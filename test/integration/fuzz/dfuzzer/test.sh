#!/bin/bash

# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: D-Bus Broker Developers

set -eux
set -o pipefail

TEST_USER="dfuzzer$SRANDOM"

at_exit() {
    userdel -rf "$TEST_USER"
}

trap at_exit EXIT
useradd "$TEST_USER"

dbus-broker --version
systemctl status --no-pager dbus-broker.service

# Run dfuzzer on the PID 1's D-Bus interface. Drop privileges while doing so, since here we're interested in
# the actual message broking instead of breaking systemd.
#
# org.freedesktop.systemd1 was picked here because its interface is very rich when it comes to function
# signatures. Also, it's fuzzed in upstream by dfuzzer as well, which should make the test less prone to fails
# due to issues on systemd's side.
setpriv --reuid="$TEST_USER" --init-group -- dfuzzer -v --buffer-limit=10240 --bus org.freedesktop.systemd1
