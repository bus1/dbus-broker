#
# Meson Integration for Rust libc Bindings
#
# This is a meson build file for the Rust crate `libc` (provided by
# `rust-lang/libc`). The build mirrors what `Cargo.toml` and `build.rs`
# of the crate specify, with the following caveats:
#
# - Currently, only cfgs relevant for linux are considered.
# - `_FILE_OFFSET_BITS=64` and `_TIME_BITS=64` are enabled unconditionally.
# - Only the stable branch `libc-0.2` is supported.
# - Last compatibility check was made with `libc-0.2.175`. Newer version
#   might have added further `build.rs` or `Cargo.toml` configurations.
#

project(
        'libc-rs-0.2',
        default_options: [
                'rust_std=2021',
        ],
        license: 'MIT OR Apache-2.0',
        meson_version: '>=1.3',
        version: '0.2',
)

add_languages('rust', native: false)

rust_edition = '2021'
rust_msv = '1.63'

rust = meson.get_compiler('rust')

#
# System Requirements
#

if rust.version().version_compare('<' + rust_msv)
        error('Found Rust ' + rust.version() + ' but requires >=' + rust_msv)
endif

cargo = find_program('cargo', native: true, required: true, version: '>=' + rust_msv)
jq = find_program('jq', native: true, required: true, version: '>=1.6')

#
# Detect version of the libc sources
#

libc_version = run_command(
        './meson-detect-version.sh',
        capture: true,
        check: true,
        env: {
                'BIN_CARGO': cargo.full_path(),
                'BIN_JQ': jq.full_path(),
        },
).stdout().strip()

summary('version', libc_version)

#
# Build libc as rust library
#

libc_rlib = static_library(
        'libc',
        ['src/lib.rs'],
        rust_args: [
                # Unconditionally enabled by `build.rs`.
                '--cfg=libc_const_extern_fn',
        ],
)

libc_dep = declare_dependency(
        link_with: libc_rlib,
        version: libc_version,
)

meson.override_dependency('libc-rs-0.2', libc_dep, static: true)
