#
# target: subdirs
#

if use_launcher
        subdir('catalog')
        subdir('units/system')
        subdir('units/user')
endif

#
# target: libbus.so
#

sources_bus = [
        'broker/broker.c',
        'broker/controller.c',
        'broker/controller-dbus.c',
        'bus/activation.c',
        'bus/bus.c',
        'bus/diag.c',
        'bus/driver.c',
        'bus/listener.c',
        'bus/match.c',
        'bus/metrics.c',
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
        'util/fs.c',
        'util/log.c',
        'util/misc.c',
        'util/nsec.c',
        'util/proc.c',
        'util/sampler.c',
        'util/sockopt.c',
        'util/string.c',
        'util/systemd.c',
        'util/user.c',
]

bindgen_bus = [
        'session/main.h',
        'util/acct.h',
]

deps_bus = [
        dep_cdvar,
        dep_clist,
        dep_crbtree,
        dep_cstdaux,
        dep_math,
]

incs_bus = include_directories('.')

if use_apparmor
        sources_bus += [
                'util/apparmor.c',
        ]
        deps_bus += [
                dep_libapparmor,
        ]
else
        sources_bus += [
                'util/apparmor-fallback.c',
        ]
endif

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

bindgen_args = [
        '--formatter', 'prettyplease',
        '--use-core',
]

if bindgen_version.version_compare('>=0.71')
        bindgen_args += [
                '--rust-edition', rust_edition,
                '--rust-target', rust_msv,
        ]
endif

bindgen_generated = []

foreach i : bindgen_bus
        bindgen_generated += mod_rust.bindgen(
                args: bindgen_args + [
                        '--allowlist-file=.*/' + i,
                ],
                c_args: [
                        # MSMV(1.9.1): With 1.9.1 this is set by Meson.
                        '-D_FILE_OFFSET_BITS=64',
                ],
                dependencies: deps_bus,
                include_directories: incs_bus,
                input: i,
                # `foo-bar.h` -> `foo_bar.rs`
                output: i.substring(0, -2).underscorify() + '.rs',
        )
endforeach

rbus_generated = static_library(
        'rbus_generated',
        structured_sources(
                [
                        'lib-generated.rs',
                ],
                {
                        'generated': bindgen_generated,
                },
        ),
)

rbus_crate = static_library(
        'rbus',
        ['lib-crate.rs'],
        dependencies: [
                dep_libc_rs,
                dep_osi,
        ],
        link_with: [
                rbus_generated,
        ],
)

rbus_static = static_library(
        'rbus_static',
        ['lib-static.rs'],
        link_with: [
                rbus_crate,
                rbus_generated,
        ],
        rust_abi: 'c',
)

static_bus = static_library(
        'bus-static',
        sources_bus,
        c_args: [
                '-fvisibility=hidden',
                '-fno-common',
        ],
        dependencies: deps_bus,
        link_with: rbus_static,
        pic: true,
)

dep_bus = declare_dependency(
        include_directories: incs_bus,
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
                'broker/main.c',
        ],
        dependencies: [
                dep_bus,
                dep_cdvar,
                dep_cstdaux,
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
                        'launch/launcher.c',
                        'launch/service.c',
                ],
                dependencies: [
                        dep_bus,
                        dep_cini,
                        dep_crbtree,
                        dep_cshquote,
                        dep_cstdaux,
                        dep_libsystemd,
                ],
                install: true,
                link_depends: [
                        exe_dbus_broker,
                ],
        )
endif

#
# target: dbus-broker-session
#

if use_launcher
        exe_dbus_broker_session = executable(
                'dbus-broker-session',
                [
                        'session/main.c',
                ],
                dependencies: [
                        dep_bus,
                ],
                install: true,
                link_depends: [
                        exe_dbus_broker,
                ],
        )
endif

#
# target: test-*
#

mod_rust.test(
        'rbus-tests',
        rbus_crate,
        suite: 'unit',
)

if use_doctest and meson.version().version_compare('>=1.8')
        mod_rust.doctest(
                'rbus-doctests',
                rbus_crate,
                suite: 'doctest',
        )
endif

test_kwargs = {
        'dependencies': dep_bus,
        'install': use_tests,
        'install_dir': conf.get('testdir') / 'unit',
}

test_address = executable('test-address', sources: ['dbus/test-address.c'], kwargs: test_kwargs)
test('Address Handling', test_address, suite: 'unit')

test_apparmor = executable('test-apparmor', sources: ['util/test-apparmor.c'], kwargs: test_kwargs)
test('AppArmor Handling', test_apparmor, suite: 'unit')

if use_launcher
        test_config = executable('test-config', sources: ['launch/test-config.c'], kwargs: test_kwargs)
        test('Configuration Parser', test_config, suite: 'unit')
endif

test_dirwatch = executable('test-dirwatch', sources: ['util/test-dirwatch.c'], kwargs: test_kwargs)
test('Directory Watch', test_dirwatch, suite: 'unit')

test_dispatch = executable('test-dispatch', sources: ['util/test-dispatch.c'], kwargs: test_kwargs)
test('Event Dispatcher', test_dispatch, suite: 'unit')

test_error = executable('test-error', sources: ['util/test-error.c'], kwargs: test_kwargs)
test('Error Handling', test_error, suite: 'unit')

test_fdlist = executable('test-fdlist', sources: ['util/test-fdlist.c'], kwargs: test_kwargs)
test('Utility File-Desciptor Lists', test_fdlist, suite: 'unit')

test_fs = executable('test-fs', sources: ['util/test-fs.c'], kwargs: test_kwargs)
test('File System Helpers', test_fs, suite: 'unit')

test_match = executable('test-match', sources: ['bus/test-match.c'], kwargs: test_kwargs)
test('D-Bus Match Handling', test_match, suite: 'unit')

test_message = executable('test-message', sources: ['dbus/test-message.c'], kwargs: test_kwargs)
test('D-Bus Message Abstraction', test_message, suite: 'unit')

test_misc = executable('test-misc', sources: ['util/test-misc.c'], kwargs: test_kwargs)
test('Miscellaneous Helpers', test_misc, suite: 'unit')

test_name = executable('test-name', sources: ['bus/test-name.c'], kwargs: test_kwargs)
test('Name Registry', test_name, suite: 'unit')

test_nsec = executable('test-nsec', sources: ['util/test-nsec.c'], kwargs: test_kwargs)
test('Nanosecond Time', test_nsec, suite: 'unit')

if use_launcher
        test_nss_cache = executable('test-nss-cache', sources: ['launch/test-nss-cache.c'], kwargs: test_kwargs)
        test('NSS Cache', test_nss_cache, suite: 'unit')
endif

test_peersec = executable('test-peersec', sources: ['util/test-peersec.c'], kwargs: test_kwargs)
test('SO_PEERSEC Queries', test_peersec, suite: 'unit')

test_proc = executable('test-proc', sources: ['util/test-proc.c'], kwargs: test_kwargs)
test('Proc Utilities', test_proc, suite: 'unit')

test_queue = executable('test-queue', sources: ['dbus/test-queue.c'], kwargs: test_kwargs)
test('D-Bus I/O Queues', test_queue, suite: 'unit')

test_reply = executable('test-reply', sources: ['bus/test-reply.c'], kwargs: test_kwargs)
test('Reply Tracking', test_reply, suite: 'unit')

test_sasl = executable('test-sasl', sources: ['dbus/test-sasl.c'], kwargs: test_kwargs)
test('D-Bus SASL Parser', test_sasl, suite: 'unit')

test_socket = executable('test-socket', sources: ['dbus/test-socket.c'], kwargs: test_kwargs)
test('D-Bus Socket Abstraction', test_socket, suite: 'unit')

test_sockopt = executable('test-sockopt', sources: ['util/test-sockopt.c'], kwargs: test_kwargs)
test('D-Bus Socket Options', test_sockopt, suite: 'unit')

test_stitching = executable('test-stitching', sources: ['dbus/test-stitching.c'], kwargs: test_kwargs)
test('Message Sender Stitching', test_stitching, suite: 'unit')

test_systemd = executable('test-systemd', sources: ['util/test-systemd.c'], kwargs: test_kwargs)
test('Systemd Utilities', test_systemd, suite: 'unit')

test_user = executable('test-user', sources: ['util/test-user.c'], kwargs: test_kwargs)
test('User Accounting', test_user, suite: 'unit')
