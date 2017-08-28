project(
        'dbus-broker',
        'c',
        version: '3',
        license: 'Apache',
        default_options: [
                'c_std=c11',
        ],
)

add_project_arguments('-D_GNU_SOURCE', language: 'c')
add_project_arguments('-DPACKAGE_VERSION=' + meson.project_version(), language: 'c')

cc = meson.get_compiler('c')
conf = configuration_data()
mod_pkgconfig = import('pkgconfig')

sub_cdvar = subproject('c-dvar', version: '>=1')
sub_clist = subproject('c-list', version: '>=3')
sub_crbtree = subproject('c-rbtree', version: '>=3')
sub_csundry = subproject('c-sundry', version: '>=1')

dep_cdvar = sub_cdvar.get_variable('libcdvar_dep')
dep_clist = sub_clist.get_variable('libclist_dep')
dep_crbtree = sub_crbtree.get_variable('libcrbtree_dep')
dep_csundry = sub_csundry.get_variable('libcsundry_dep')
dep_dbus = dependency('dbus-1', version: '>=1.10', required: false)
dep_glib = dependency('glib-2.0', version: '>=2.50', required: false)
dep_libsystemd = dependency('libsystemd', version: '>=230', required: false)
dep_math = cc.find_library('m')
dep_systemd = dependency('systemd', required: false)
dep_thread = dependency('threads')
dep_expat = dependency('expat')

use_audit = get_option('audit')
if use_audit
        dep_libaudit = dependency('audit', version: '>=2.7')
endif

use_selinux = get_option('selinux')
if use_selinux
        dep_libselinux = dependency('libselinux', version: '>=2.5')
endif

conf.set('bindir', join_paths(get_option('prefix'), get_option('bindir')))

if dep_systemd.found()
        conf.set('systemunitdir', dep_systemd.get_pkgconfig_variable('systemdsystemunitdir'))
        conf.set('userunitdir', dep_systemd.get_pkgconfig_variable('systemduserunitdir'))
endif

subdir('src')

if dep_systemd.found()
        subdir('test/dbus')
        subdir('units/system')
        subdir('units/user')
endif
