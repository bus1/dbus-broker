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
                libdbus_broker_dep,
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

test_driver = executable('test-driver', ['test-driver.c'], dependencies: [ libtest_dep ])
test('Driver API', test_driver)

test_fdstream = executable('test-fdstream', ['test-fdstream.c'], dependencies: [ libtest_dep ])
test('FD Stream Constraints', test_fdstream)

test_lifetime = executable('test-lifetime', ['test-lifetime.c'], dependencies: [ libtest_dep ])
test('Client Lifetime', test_lifetime)

if use_reference_test
        dbus_bin = dep_dbus.get_pkgconfig_variable('bindir') + '/dbus-daemon'

        test('dbus-daemon(1): Broker API', test_broker, env: [ 'DBUS_BROKER_TEST_DAEMON=' + dbus_bin ])
        test('dbus-daemon(1): Driver API', test_driver, env: [ 'DBUS_BROKER_TEST_DAEMON=' + dbus_bin ])
        test('dbus-daemon(1): FD Stream Constraints', test_fdstream, env: [ 'DBUS_BROKER_TEST_DAEMON=' + dbus_bin ])
        test('dbus-daemon(1): Client Lifetime', test_lifetime, env: [ 'DBUS_BROKER_TEST_DAEMON=' + dbus_bin ])
endif
