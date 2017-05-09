#
# target: libdbus-broker.so
#

libdbus_broker_private = static_library(
        'dbus-broker-private',
        [
                'bus.c',
                'dbus/connection.c',
                'dbus/message.c',
                'dbus/sasl.c',
                'dbus/socket.c',
                'dbus/unique-name.c',
                'activation.c',
                'driver.c',
                'listener.c',
                'match.c',
                'name.c',
                'peer.c',
                'reply.c',
                'user.c',
                'util/error.c',
                'util/dispatch.c',
                'util/fdlist.c',
                'util/metrics.c',
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
                'broker/controller.c',
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
# target: dbus-broker-launch
#

if dep_systemd.found()
        exe_dbus_broker_launch = executable(
                'dbus-broker-launch',
                [
                        'launch/main.c',
                ],
                dependencies: [
                        dep_csundry,
                        dep_systemd,
                        libdbus_broker_dep,
                ],
                install: true,
        )
endif

#
# target: test-*
#

if dep_systemd.found()
        test_broker = executable('test-broker', ['broker/test-broker.c'], dependencies: [ libdbus_broker_dep, dep_thread, dep_systemd ])
        test('Instance of broker + controller', test_broker)
endif

test_dispatch = executable('test-dispatch', ['util/test-dispatch.c'], dependencies: libdbus_broker_dep)
test('Event Dispatcher', test_dispatch)

test_fdlist = executable('test-fdlist', ['util/test-fdlist.c'], dependencies: libdbus_broker_dep)
test('Utility File-Desciptor Lists', test_fdlist)

test_match = executable('test-match', ['test-match.c'], dependencies: libdbus_broker_dep)
test('D-Bus Match Handling', test_match)

test_message = executable('test-message', ['dbus/test-message.c'], dependencies: libdbus_broker_dep)
test('D-Bus Message Abstraction', test_message)

test_name = executable('test-name', ['test-name.c'], dependencies: libdbus_broker_dep)
test('Name Registry', test_name)

test_reply = executable('test-reply', ['test-reply.c'], dependencies: libdbus_broker_dep)
test('Reply Tracking', test_reply)

test_sasl = executable('test-sasl', ['dbus/test-sasl.c'], dependencies: libdbus_broker_dep)
test('D-Bus SASL Parser', test_sasl)

test_socket = executable('test-socket', ['dbus/test-socket.c'], dependencies: libdbus_broker_dep)
test('D-Bus Socket Abstraction', test_socket)

test_stitching = executable('test-stitching', ['dbus/test-stitching.c'], dependencies: libdbus_broker_dep)
test('Message Sender Stitching', test_stitching)

test_unique_name = executable('test-unique-name', ['dbus/test-unique-name.c'], dependencies: libdbus_broker_dep)
test('Unique Name Handling', test_unique_name)

test_user = executable('test-user', ['test-user.c'], dependencies: libdbus_broker_dep)
test('User Accounting', test_user)
