#
# target: libtest.so
#

libtest_private = static_library(
        'test-private',
        [
                'util-broker.c',
        ],
        c_args: [
                '-fvisibility=hidden',
                '-fno-common',
        ],
        dependencies: [
                dep_csundry,
                dep_libsystemd,
                dep_thread,
        ],
        pic: true,
)

libtest_dep = declare_dependency(
        include_directories: include_directories('.'),
        link_with: libtest_private,
        dependencies: [
                dep_csundry,
                dep_libsystemd,
                dep_thread,
                libdbus_broker_dep,
        ],
        version: meson.project_version(),
)

#
# target: test-*
#

test_broker = executable('test-broker', ['test-broker.c'], dependencies: [ libtest_dep ])
test('Broker API', test_broker)

test_fdstream = executable('test-fdstream', ['test-fdstream.c'], dependencies: [ libtest_dep ])
test('FD Stream Constraints', test_fdstream)

test_fdspam = executable('test-fdspam', ['test-fdspam.c'], dependencies: [ libtest_dep ])
test('FD Spam Protection', test_fdspam)

if dep_dbus.found()
        dbus_bin = dep_dbus.get_pkgconfig_variable('bindir') + '/dbus-daemon'

        test('dbus-daemon(1): Broker API', test_broker, env: [ 'DBUS_BROKER_TEST_DAEMON=' + dbus_bin ])
        test('dbus-daemon(1): FD Stream Constraints', test_fdstream, env: [ 'DBUS_BROKER_TEST_DAEMON=' + dbus_bin ])
        test('dbus-daemon(1): FD Spam Protections', test_fdspam, env: [ 'DBUS_BROKER_TEST_DAEMON=' + dbus_bin ])
endif
