#
# target: libtest.so
#

sources_test = [
        'util-broker.c',
        'util-message.c',
]

deps_test = [
        dep_bus,
        dep_cstdaux,
        dep_libsystemd,
        dep_thread,
]

targets_test = [
        exe_dbus_broker,
]

static_test = static_library(
        'test-private',
        sources_test,
        c_args: [
                '-fvisibility=hidden',
                '-fno-common',
        ],
        dependencies: deps_test,
        pic: true,
        link_depends: targets_test,
)

dep_test = declare_dependency(
        include_directories: include_directories('.'),
        link_with: static_test,
        dependencies: deps_test,
        version: meson.project_version(),
)

#
# target: tool-*
#

tool_flood = executable('tool-flood', ['tool-flood.c'], dependencies: [ dep_test ])

#
# target: bench-*
#

bench_connect = executable('bench-connect', ['bench-connect.c'], dependencies: [ dep_test ])
benchmark('Connection', bench_connect)

bench_message = executable('bench-message', ['bench-message.c'], dependencies: [ dep_test ])
benchmark('Message passing', bench_message)

#
# target: test-*
#

test_broker = executable('test-broker', ['test-broker.c'], dependencies: [ dep_test ])
test('Broker API', test_broker)

test_driver = executable('test-driver', ['test-driver.c'], dependencies: [ dep_test ])
test('Driver API', test_driver)

test_fdstream = executable('test-fdstream', ['test-fdstream.c'], dependencies: [ dep_test ])
test('FD Stream Constraints', test_fdstream)

test_lifetime = executable('test-lifetime', ['test-lifetime.c'], dependencies: [ dep_test ])
test('Client Lifetime', test_lifetime)

test_matches = executable('test-matches', ['test-matches.c'], dependencies: [ dep_test ])
test('Signals and Matches', test_matches)

if use_reference_test
        dbus_bin = dep_dbus.get_pkgconfig_variable('bindir') + '/dbus-daemon'

        benchmark('dbus-daemon(1): Connection', bench_connect, env: [ 'DBUS_BROKER_TEST_DAEMON=' + dbus_bin ], timeout: 60)
        benchmark('dbus-daemon(1): Message passing', bench_message, env: [ 'DBUS_BROKER_TEST_DAEMON=' + dbus_bin ], timeout: 120)

        test('dbus-daemon(1): Broker API', test_broker, env: [ 'DBUS_BROKER_TEST_DAEMON=' + dbus_bin ])
        test('dbus-daemon(1): Driver API', test_driver, env: [ 'DBUS_BROKER_TEST_DAEMON=' + dbus_bin ])
        test('dbus-daemon(1): FD Stream Constraints', test_fdstream, env: [ 'DBUS_BROKER_TEST_DAEMON=' + dbus_bin ])
        test('dbus-daemon(1): Client Lifetime', test_lifetime, env: [ 'DBUS_BROKER_TEST_DAEMON=' + dbus_bin ])
        test('dbus-daemon(1): Signals and Matches', test_matches, env: [ 'DBUS_BROKER_TEST_DAEMON=' + dbus_bin ])
endif
