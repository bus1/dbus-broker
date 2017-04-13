project('dbus-broker',
        'c',
        version: '1',
        license: 'Apache',
        default_options: [ 'c_std=c11' ])

add_project_arguments('-D_GNU_SOURCE', language: 'c')
add_project_arguments('-DPACKAGE_VERSION=' + meson.project_version(), language: 'c')
mod_pkgconfig = import('pkgconfig')
dep_cdvar = dependency('libcdvar', version: '>=1', fallback: [ 'c-dvar', 'libcdvar_dep' ])
dep_clist = dependency('libclist', version: '>=1', fallback: [ 'c-list', 'libclist_dep' ])
dep_crbtree = dependency('libcrbtree', version: '>=2', fallback: [ 'c-rbtree', 'libcrbtree_dep' ])
dep_csundry = dependency('libcsundry', version: '>=1', fallback: [ 'c-sundry', 'libcsundry_dep' ])
dep_systemd = dependency('libsystemd', version: '>=230', required: false)
dep_thread = dependency('threads')

subdir('src')
