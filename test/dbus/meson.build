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
        ],
        version: meson.project_version(),
)

#
# target: test-*
#

test_broker = executable('test-broker', ['test-broker.c'], dependencies: [ libtest_dep, dep_libsystemd ])
test('Broker API', test_broker)
