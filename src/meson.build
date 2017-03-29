#
# target: libdbus-broker.so
# We build an internal, shared library with all the bits used by the broker.
# This library is then linked into the real broker, but also all our internal
# tests.
#

libdbus_broker_private = static_library('dbus-broker-private',
                                        [
                                                'bus.c',
                                                'dbus-match.c',
                                                'dbus-message.c',
                                                'dbus-sasl.c',
                                                'dbus-socket.c',
                                                'dbus-variant.c',
                                                'dispatch.c',
                                                'driver.c',
                                                'name.c',
                                                'peer.c',
                                                'user.c',
                                        ],
                                        c_args: [
                                                '-fvisibility=hidden',
                                                '-fno-common',
                                        ],
                                        dependencies: [
                                                dep_clist,
                                                dep_crbtree,
                                                dep_csundry,
                                        ],
                                        pic: true)
libdbus_broker_dep = declare_dependency(include_directories: include_directories('.'),
                                        link_with: libdbus_broker_private,
                                        dependencies: [
                                                dep_clist,
                                                dep_crbtree,
                                                dep_csundry,
                                        ],
                                        version: meson.project_version())

#
# target: test-*
# Bunch of tests for broker internals. They all link against the static broker
# library so they get access to all internal functions and state.
#

test_bus = executable('test-bus', ['test-bus.c'], dependencies: libdbus_broker_dep)
test('Bus Management', test_bus)

test_match = executable('test-match', ['test-match.c'], dependencies: libdbus_broker_dep)
test('D-Bus Match Handling', test_match)

test_message = executable('test-message', ['test-message.c'], dependencies: libdbus_broker_dep)
test('D-Bus Message Abstraction', test_message)

test_name = executable('test-name', ['test-name.c'], dependencies: libdbus_broker_dep)
test('Name Registry', test_name)

test_peer = executable('test-peer', ['test-peer.c'], dependencies: libdbus_broker_dep)
test('Peer Handling', test_peer)

test_sasl = executable('test-sasl', ['test-sasl.c'], dependencies: libdbus_broker_dep)
test('D-Bus SASL Parser', test_sasl)

test_socket = executable('test-socket', ['test-socket.c'], dependencies: libdbus_broker_dep)
test('D-Bus Socket Abstraction', test_socket)

test_user = executable('test-user', ['test-user.c'], dependencies: libdbus_broker_dep)
test('User Accounting', test_user)

test_variant = executable('test-variant', ['test-variant.c'], dependencies: libdbus_broker_dep)
test('D-Bus Variant Builder and Parser', test_variant)
