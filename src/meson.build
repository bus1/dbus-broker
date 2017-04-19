#
# target: libdbus-broker.so
#

libdbus_broker_private = static_library(
        'dbus-broker-private',
        [
                'bus.c',
                'connection.c',
                'driver.c',
                'match.c',
                'message.c',
                'name.c',
                'peer.c',
                'reply.c',
                'sasl.c',
                'socket.c',
                'user.c',
                'util/dispatch.c',
                'util/fdlist.c',
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
        ],
        version: meson.project_version(),
)

#
# target: dbus-broker
#

exe_dbus_broker = executable(
        'dbus-broker',
        [
                'broker/main.c',
                'broker/manager.c',
        ],
        dependencies: [
                dep_clist,
                dep_csundry,
                libdbus_broker_dep,
        ],
        install: true,
)

#
# target: test-*
#

if dep_systemd.found()
        test_broker = executable('test-broker', ['test-broker.c'], dependencies: [ libdbus_broker_dep, dep_thread, dep_systemd ])
        test('In-process broker', test_broker)
endif

test_bus = executable('test-bus', ['test-bus.c'], dependencies: libdbus_broker_dep)
test('Bus Management', test_bus)

test_dispatch = executable('test-dispatch', ['util/test-dispatch.c'], dependencies: libdbus_broker_dep)
test('Event Dispatcher', test_dispatch)

test_fdlist = executable('test-fdlist', ['test-fdlist.c'], dependencies: libdbus_broker_dep)
test('Utility File-Desciptor Lists', test_fdlist)

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
