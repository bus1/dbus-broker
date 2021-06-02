#
# Global Project Setup
#

project(
        'dbus-broker',
        'c',
        version: '29',
        license: 'Apache',
        default_options: [
                'c_std=c11',
        ],
)

add_project_arguments('-D_GNU_SOURCE', language: 'c')
add_project_arguments('-DPACKAGE_VERSION=' + meson.project_version(), language: 'c')
add_project_arguments('-DBINDIR="' + join_paths(get_option('prefix'), get_option('bindir')) + '"', language: 'c')

cc = meson.get_compiler('c')
conf = configuration_data()
mod_pkgconfig = import('pkgconfig')

#
# Mandatory Dependencies
#

sub_cdvar = subproject('c-dvar', version: '>=1')
sub_cini = subproject('c-ini', version: '>=1')
sub_clist = subproject('c-list', version: '>=3')
sub_crbtree = subproject('c-rbtree', version: '>=3')
sub_cshquote = subproject('c-shquote', version: '>=1')
sub_cstdaux = subproject('c-stdaux', version: '>=1')

dep_cdvar = sub_cdvar.get_variable('libcdvar_dep')
dep_cini = sub_cini.get_variable('libcini_dep')
dep_clist = sub_clist.get_variable('libclist_dep')
dep_crbtree = sub_crbtree.get_variable('libcrbtree_dep')
dep_cshquote = sub_cshquote.get_variable('libcshquote_dep')
dep_cstdaux = sub_cstdaux.get_variable('libcstdaux_dep')
dep_math = cc.find_library('m')
dep_thread = dependency('threads')

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

        add_project_arguments('-DSYSTEMUIDMAX=' + dep_systemd.get_pkgconfig_variable('systemuidmax'), language: 'c')
        conf.set('systemunitdir', dep_systemd.get_pkgconfig_variable('systemdsystemunitdir'))
        conf.set('userunitdir', dep_systemd.get_pkgconfig_variable('systemduserunitdir'))
        conf.set('catalogdir', dep_systemd.get_pkgconfig_variable('catalogdir'))
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
