#
# target: /usr/lib/systemd/user/dbus-broker.service
#

configure_file(
        input: 'dbus-broker.service.in',
        output: 'dbus-broker.service',
        configuration: conf,
        install_dir: conf.get('userunitdir'),
)
