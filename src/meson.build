#
# target: subdirs
#

if use_launcher
        subdir('units/system')
        subdir('units/user')
endif

#
# target: libdbus-broker.so
#

libdbus_broker_sources = [
        'bus/activation.c',
        'bus/bus.c',
        'bus/driver.c',
        'bus/listener.c',
        'bus/match.c',
        'bus/name.c',
        'bus/peer.c',
        'bus/policy.c',
        'bus/reply.c',
        'dbus/address.c',
        'dbus/connection.c',
        'dbus/message.c',
        'dbus/protocol.c',
        'dbus/queue.c',
        'dbus/sasl.c',
        'dbus/socket.c',
        'util/error.c',
        'util/dispatch.c',
        'util/fdlist.c',
        'util/log.c',
        'util/metrics.c',
        'util/proc.c',
        'util/sockopt.c',
        'util/user.c',
]

libdbus_broker_dependencies = [
        dep_cdvar,
        dep_clist,
        dep_crbtree,
        dep_csundry,
        dep_expat,
]

if use_audit
        libdbus_broker_sources += [
                'util/audit.c',
        ]
        libdbus_broker_dependencies += [
                dep_libaudit,
        ]
else
        libdbus_broker_sources += [
                'util/audit-fallback.c',
        ]
endif

if use_selinux
        libdbus_broker_sources += [
                'util/selinux.c',
        ]
        libdbus_broker_dependencies += [
                dep_libselinux,
        ]
else
        libdbus_broker_sources += [
                'util/selinux-fallback.c',
        ]
endif

libdbus_broker_private = static_library(
        'dbus-broker-private',
        libdbus_broker_sources,
        c_args: [
                '-fvisibility=hidden',
                '-fno-common',
        ],
        dependencies: libdbus_broker_dependencies,
        pic: true,
)

libdbus_broker_dep = declare_dependency(
        include_directories: include_directories('.'),
        link_with: libdbus_broker_private,
        dependencies: [
                dep_cdvar,
                dep_clist,
                dep_crbtree,
                dep_csundry,
                dep_math,
        ],
        version: meson.project_version(),
)

#
# target: dbus-broker
#

exe_dbus_broker = executable(
        'dbus-broker',
        [
                'broker/broker.c',
                'broker/controller.c',
                'broker/controller-dbus.c',
                'broker/main.c',
        ],
        dependencies: [
                dep_clist,
                dep_csundry,
                libdbus_broker_dep,
        ],
        install: true,
)

#
# target: dbus-broker-launch
#

if use_launcher
        exe_dbus_broker_launch = executable(
                'dbus-broker-launch',
                [
                        'launch/config.c',
                        'launch/main.c',
                        'launch/nss-cache.c',
                        'launch/policy.c',
                ],
                dependencies: [
                        dep_crbtree,
                        dep_csundry,
                        dep_glib,
                        dep_libsystemd,
                        libdbus_broker_dep,
                ],
                install: true,
        )
endif

#
# target: test-*
#

test_address = executable('test-address', ['dbus/test-address.c'], dependencies: libdbus_broker_dep)
test('Address Handling', test_address)

test_config = executable('test-config', ['launch/test-config.c', 'launch/config.c', 'launch/nss-cache.c'], dependencies: libdbus_broker_dep)
test('Configuration Parser', test_config)

test_dispatch = executable('test-dispatch', ['util/test-dispatch.c'], dependencies: libdbus_broker_dep)
test('Event Dispatcher', test_dispatch)

test_error = executable('test-error', ['util/test-error.c'], dependencies: libdbus_broker_dep)
test('Error Handling', test_error)

test_fdlist = executable('test-fdlist', ['util/test-fdlist.c'], dependencies: libdbus_broker_dep)
test('Utility File-Desciptor Lists', test_fdlist)

test_match = executable('test-match', ['bus/test-match.c'], dependencies: libdbus_broker_dep)
test('D-Bus Match Handling', test_match)

test_message = executable('test-message', ['dbus/test-message.c'], dependencies: libdbus_broker_dep)
test('D-Bus Message Abstraction', test_message)

test_name = executable('test-name', ['bus/test-name.c'], dependencies: libdbus_broker_dep)
test('Name Registry', test_name)

test_queue = executable('test-queue', ['dbus/test-queue.c'], dependencies: libdbus_broker_dep)
test('D-Bus I/O Queues', test_queue)

test_reply = executable('test-reply', ['bus/test-reply.c'], dependencies: libdbus_broker_dep)
test('Reply Tracking', test_reply)

test_sasl = executable('test-sasl', ['dbus/test-sasl.c'], dependencies: libdbus_broker_dep)
test('D-Bus SASL Parser', test_sasl)

test_socket = executable('test-socket', ['dbus/test-socket.c'], dependencies: libdbus_broker_dep)
test('D-Bus Socket Abstraction', test_socket)

test_stitching = executable('test-stitching', ['dbus/test-stitching.c'], dependencies: libdbus_broker_dep)
test('Message Sender Stitching', test_stitching)

test_user = executable('test-user', ['util/test-user.c'], dependencies: libdbus_broker_dep)
test('User Accounting', test_user)
