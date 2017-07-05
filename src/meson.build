#
# target: libdbus-broker.so
#

libdbus_broker_private = static_library(
        'dbus-broker-private',
        [
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
                'dbus/sasl.c',
                'dbus/socket.c',
                'launch/policy-parser.c', # XXX: drop once pre-parsed
                'util/error.c',
                'util/dispatch.c',
                'util/fdlist.c',
                'util/metrics.c',
                'util/user.c',
        ],
        c_args: [
                '-fvisibility=hidden',
                '-fno-common',
        ],
        dependencies: [
                dep_cdvar,
                dep_clist,
                dep_crbtree,
                dep_csundry,
                dep_expat,
        ],
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

if dep_libsystemd.found() and dep_glib.found()
        exe_dbus_broker_launch = executable(
                'dbus-broker-launch',
                [
                        'launch/main.c',
                        'launch/policy-parser.c',
                        'bus/policy.c',
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

if dep_libsystemd.found()
        test_broker = executable('test-broker', ['broker/test-broker.c'], dependencies: [ libdbus_broker_dep, dep_thread, dep_libsystemd ])
        test('Instance of broker + controller', test_broker)

        test_driver = executable('test-driver', ['broker/test-driver.c'], dependencies: [ libdbus_broker_dep, dep_thread, dep_libsystemd ])
        test('Driver API', test_driver)
endif

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

test_policy_parser = executable('test-policy-parser', ['launch/test-policy-parser.c', 'launch/policy-parser.c'], dependencies: libdbus_broker_dep)
test('Policy Database Parser', test_policy_parser)

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
