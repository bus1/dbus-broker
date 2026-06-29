# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: D-Bus Broker Developers

#
# target: /usr/lib/systemd/system/dbus-broker.service
#

configure_file(
        input: 'dbus-broker.service.in',
        output: 'dbus-broker.service',
        configuration: conf,
        install_dir: conf.get('systemunitdir'),
)
