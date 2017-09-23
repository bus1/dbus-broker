custom_target(
        'man-dbus-broker',
        output: 'dbus-broker.1',
        input: 'dbus-broker.rst',
        command: [prog_rst2man, '@INPUT@', '@OUTPUT@'],
        install: true,
        install_dir: join_paths(get_option('mandir'), 'man1')
)

if use_launcher
        custom_target(
                'man-dbus-broker-launch',
                 output: 'dbus-broker-launch.1',
                 input: 'dbus-broker-launch.rst',
                 command: [prog_rst2man, '@INPUT@', '@OUTPUT@'],
                 install: true,
                 install_dir: join_paths(get_option('mandir'), 'man1')
        )
endif
