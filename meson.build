#
# Global Project Setup
#

project(
        'dbus-broker',
        'c',
        default_options: [
                'c_std=c11',
        ],
        license: 'Apache',
        meson_version: '>=0.60.0',
        version: '34',
)

cc = meson.get_compiler('c')
conf = configuration_data()
mod_pkgconfig = import('pkgconfig')

#
# Mandatory Dependencies
#

dep_cdvar = dependency('libcdvar-1', version: '>=1.1.0')
dep_cini = dependency('libcini-1', version: '>=1.1.0')
dep_clist = dependency('libclist-3', version: '>=3.1.0')
dep_crbtree = dependency('libcrbtree-3', version: '>=3.2.0')
dep_cshquote = dependency('libcshquote-1', version: '>=1.1.0')
dep_cstdaux = dependency('libcstdaux-1', version: '>=1.5.0')
dep_math = cc.find_library('m')
dep_thread = dependency('threads')

#
# Default CFLAGS
#

add_project_arguments(dep_cstdaux.get_variable('cflags').split(' '), language: 'c')
add_project_arguments('-DBINDIR="' + join_paths(get_option('prefix'), get_option('bindir')) + '"', language: 'c')
add_project_arguments('-DPACKAGE_VERSION=' + meson.project_version(), language: 'c')

#
# Config: apparmor
#

use_apparmor = get_option('apparmor')
if use_apparmor
        dep_libapparmor = dependency('libapparmor', version: '>=3.0')
endif

#
# Config: audit
#

use_audit = get_option('audit')
if use_audit
        dep_libaudit = dependency('audit', version: '>=3.0')
        dep_libcapng = dependency('libcap-ng', version: '>=0.6')
endif

#
# Config: docs
#

use_docs = get_option('docs')
if use_docs
        prog_rst2man = find_program('rst2man', 'rst2man.py')
endif

#
# Config: launcher
#

use_launcher = get_option('launcher')
if use_launcher
        dep_expat = dependency('expat', version: '>=2.2')
        dep_libsystemd = dependency('libsystemd', version: '>=230')
        dep_systemd = dependency('systemd', version: '>=230')

        add_project_arguments('-DSYSTEMUIDMAX=' + dep_systemd.get_variable('systemuidmax'), language: 'c')
        conf.set('systemunitdir', dep_systemd.get_variable('systemdsystemunitdir'))
        conf.set('userunitdir', dep_systemd.get_variable('systemduserunitdir'))
        conf.set('catalogdir', dep_systemd.get_variable('catalogdir'))
endif

#
# Config: reference-test
#

use_reference_test = get_option('reference-test')
if use_reference_test
        dep_dbus = dependency('dbus-1', version: '>=1.10')
endif

#
# Config: selinux
#

use_selinux = get_option('selinux')
if use_selinux
        dep_libselinux = dependency('libselinux', version: '>=3.2')
endif

#
# Config: system-console-users
#

use_system_console_users = get_option('system-console-users')

acc_sysusers = ''
foreach user : use_system_console_users
        acc_sysusers += '"' + user + '",'
endforeach

add_project_arguments('-DSYSTEM_CONSOLE_USERS=' + acc_sysusers, language: 'c')

#
# Global Parameters
#

conf.set('bindir', join_paths(get_option('prefix'), get_option('bindir')))

#
# Subdirs
#

subdir('src')

if use_docs
        subdir('docs')
endif

if use_launcher
        subdir('test/dbus')
endif
