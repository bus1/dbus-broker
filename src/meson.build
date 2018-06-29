#
# target: subdirs
#

if use_launcher
        subdir('units/system')
        subdir('units/user')
endif

#
# target: libbus.so
#

sources_bus = [
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
        'util/dirwatch.c',
        'util/dispatch.c',
        'util/fdlist.c',
        'util/log.c',
        'util/metrics.c',
        'util/misc.c',
        'util/proc.c',
        'util/sockopt.c',
        'util/user.c',
]

deps_bus = [
        dep_cdvar,
        dep_clist,
        dep_crbtree,
        dep_csundry,
        dep_math,
]

if use_audit
        sources_bus += [
                'util/audit.c',
        ]
        deps_bus += [
                dep_libaudit,
                dep_libcapng,
        ]
else
        sources_bus += [
                'util/audit-fallback.c',
        ]
endif

if use_launcher
        sources_bus += [
                'launch/config.c',
                'launch/nss-cache.c',
                'launch/policy.c',
        ]
        deps_bus += [
                dep_expat,
                dep_libsystemd,
        ]
endif

if use_selinux
        sources_bus += [
                'util/selinux.c',
        ]
        deps_bus += [
                dep_libselinux,
        ]
else
        sources_bus += [
                'util/selinux-fallback.c',
        ]
endif

static_bus = static_library(
        'bus-static',
        sources_bus,
        c_args: [
                '-fvisibility=hidden',
                '-fno-common',
        ],
        dependencies: deps_bus,
        pic: true,
)

dep_bus = declare_dependency(
        include_directories: include_directories('.'),
        link_with: static_bus,
        dependencies: deps_bus,
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
                dep_bus,
                dep_cdvar,
                dep_csundry,
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
                        'launch/main.c',
                ],
                dependencies: [
                        dep_bus,
                        dep_crbtree,
                        dep_csundry,
                        dep_glib,
                        dep_libsystemd,
                ],
                install: true,
        )
endif

#
# target: test-*
#

test_address = executable('test-address', ['dbus/test-address.c'], dependencies: dep_bus)
test('Address Handling', test_address)

test_config = executable('test-config', ['launch/test-config.c'], dependencies: dep_bus)
test('Configuration Parser', test_config)

test_dirwatch = executable('test-dirwatch', ['util/test-dirwatch.c'], dependencies: dep_bus)
test('Directory Watch', test_dirwatch)

test_dispatch = executable('test-dispatch', ['util/test-dispatch.c'], dependencies: dep_bus)
test('Event Dispatcher', test_dispatch)

test_error = executable('test-error', ['util/test-error.c'], dependencies: dep_bus)
test('Error Handling', test_error)

test_fdlist = executable('test-fdlist', ['util/test-fdlist.c'], dependencies: dep_bus)
test('Utility File-Desciptor Lists', test_fdlist)

test_match = executable('test-match', ['bus/test-match.c'], dependencies: dep_bus)
test('D-Bus Match Handling', test_match)

test_message = executable('test-message', ['dbus/test-message.c'], dependencies: dep_bus)
test('D-Bus Message Abstraction', test_message)

test_name = executable('test-name', ['bus/test-name.c'], dependencies: dep_bus)
test('Name Registry', test_name)

test_nss_cache = executable('test-nss-cache', ['launch/test-nss-cache.c'], dependencies: dep_bus)
test('NSS Cache', test_nss_cache)

test_peersec = executable('test-peersec', ['util/test-peersec.c'], dependencies: dep_bus)
test('SO_PEERSEC Queries', test_peersec)

test_queue = executable('test-queue', ['dbus/test-queue.c'], dependencies: dep_bus)
test('D-Bus I/O Queues', test_queue)

test_reply = executable('test-reply', ['bus/test-reply.c'], dependencies: dep_bus)
test('Reply Tracking', test_reply)

test_sasl = executable('test-sasl', ['dbus/test-sasl.c'], dependencies: dep_bus)
test('D-Bus SASL Parser', test_sasl)

test_socket = executable('test-socket', ['dbus/test-socket.c'], dependencies: dep_bus)
test('D-Bus Socket Abstraction', test_socket)

test_stitching = executable('test-stitching', ['dbus/test-stitching.c'], dependencies: dep_bus)
test('Message Sender Stitching', test_stitching)

test_user = executable('test-user', ['util/test-user.c'], dependencies: dep_bus)
test('User Accounting', test_user)
