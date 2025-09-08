#!/bin/bash
#
# Run `cargo metadata` to figure out the actual version of the local crate.
# Print this on `stdout` and exit with 0.
#
# Paths to `cargo`, `jq`, the meson source root and subdir can be passed via
# environment variables.

set -eo pipefail

BIN_CARGO="${BIN_CARGO:-"cargo"}"
BIN_JQ="${BIN_JQ:-"jq"}"
MESON_SOURCE_ROOT="${MESON_SOURCE_ROOT:-"."}"
MESON_SUBDIR="${MESON_SUBDIR:-"."}"

${BIN_CARGO} \
        metadata \
                --format-version 1 \
                --frozen \
                --manifest-path "${MESON_SOURCE_ROOT}/${MESON_SUBDIR}/Cargo.toml" \
                --no-deps \
        | ${BIN_JQ} \
                -cer \
                '.packages | map(select(.name == "libc")) | .[0].version'
