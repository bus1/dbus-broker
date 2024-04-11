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

tool_flood = executable('tool-flood', ['tool-flood.c'], dependencies: [dep_test])

#
# target: bench-* / test-*
#

test_kwargs = {
        'dependencies': [dep_test],
        'install': use_tests,
        'install_dir': conf.get('testdir') / 'dbus',
}

bench_connect = executable('bench-connect', sources: ['bench-connect.c'], kwargs: test_kwargs)
bench_message = executable('bench-message', sources: ['bench-message.c'], kwargs: test_kwargs)

test_broker = executable('test-broker', sources: ['test-broker.c'], kwargs: test_kwargs)
test_driver = executable('test-driver', sources: ['test-driver.c'], kwargs: test_kwargs)
test_fdstream = executable('test-fdstream', sources: ['test-fdstream.c'], kwargs: test_kwargs)
test_lifetime = executable('test-lifetime', sources: ['test-lifetime.c'], kwargs: test_kwargs)
test_matches = executable('test-matches', sources: ['test-matches.c'], kwargs: test_kwargs)

suites = [
        { 'suite': 'dbus-broker', 'env': ['DBUS_BROKER_TEST_BROKER=' + exe_dbus_broker.full_path()]},
]

if use_reference_test
        dbus_daemon_bin = dep_dbus.get_variable(pkgconfig: 'bindir') / 'dbus-daemon'
        suites += [
                { 'suite': 'dbus-daemon', 'env': ['DBUS_BROKER_TEST_DAEMON=' + dbus_daemon_bin]},
        ]
endif

foreach suite : suites
        benchmark('Connection', bench_connect, timeout: 60, kwargs: suite)
        benchmark('Message passing', bench_message, timeout: 120, kwargs: suite)

        test('Broker API', test_broker, kwargs: suite)
        test('Driver API', test_driver, kwargs: suite)
        test('FD Stream Constraints', test_fdstream, kwargs: suite)
        test('Client Lifetime', test_lifetime, kwargs: suite)
        test('Signals and Matches', test_matches, kwargs: suite)
endforeach
