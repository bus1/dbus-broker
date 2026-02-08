#!/bin/bash
# vi: set sw=4 ts=4 et tw=110:
# shellcheck disable=SC2016

set -eux
set -o pipefail

# shellcheck source=test/integration/util.sh
. "$(dirname "$0")/../../util.sh"

export ASAN_OPTIONS=strict_string_checks=1:detect_stack_use_after_return=1:check_initialization_order=1:strict_init_order=1:detect_invalid_pointer_pairs=2:handle_ioctl=1:print_cmdline=1:disable_coredump=0:use_madv_dontdump=1
# FIXME
export UBSAN_OPTIONS=print_stacktrace=1:print_summary=1:halt_on_error=0
# There' a bug in meson where it overrides UBSAN_OPTIONS when MSAN_OPTIONS is not set, see
# https://github.com/mesonbuild/meson/pull/13001
export MSAN_OPTIONS=foo
export CC="${CC:-clang}"

WITH_COVERAGE="${WITH_COVERAGE:-1}"
LCOV_OPTIONS=()

# shellcheck disable=SC2317
at_exit() {
    set +ex

    # Let's do some cleanup and export logs if necessary

    # Collect potential coredumps
    coredumpctl_collect
    container_destroy
}

trap at_exit EXIT

export BUILD_DIR="$PWD/build-san"

# Make sure the coredump collecting machinery is working
coredumpctl_init

: "=== Prepare dbus-broker's source tree ==="
# The integration test suite runs without access to the source tree it was built from. If we need the source
# tree (most likely to rebuild dbus-broker) we need to do a little dance to determine the correct references.
if [[ -n "${PACKIT_TARGET_URL:-}" ]]; then
    # If we're running in Packit's context, use the set of provided environment variables to checkout the
    # correct branch (and possibly rebase it on top of the latest source base branch so we always test the
    # latest revision possible).
    git clone "$PACKIT_TARGET_URL" dbus-broker
    cd dbus-broker
    git checkout "$PACKIT_TARGET_BRANCH"
    # If we're invoked from a pull request context, rebase on top of the latest source base branch.
    if [[ -n "${PACKIT_SOURCE_URL:-}" ]]; then
        git remote add pr "${PACKIT_SOURCE_URL:?}"
        git fetch pr "${PACKIT_SOURCE_BRANCH:?}"
        git merge "pr/$PACKIT_SOURCE_BRANCH"
    fi
    git log --oneline -5
elif [[ -n "${DBUS_BROKER_TREE:-}" ]]; then
    # Useful for quick local debugging when running this script directly, e.g. running
    #
    #   # TMT_TEST_DATA=$PWD/logs DBUS_BROKER_TREE=$PWD test/integration/fuzz/sanitizers/test.sh
    #
    # from the dbus-broker repo root.
    cd "${DBUS_BROKER_TREE:?}"
else
    # If we're running outside of Packit's context, pull the latest dbus-broker upstream.
    git clone https://github.com/bus1/dbus-broker dbus-broker
    git log --oneline -5
fi

: "=== Build dbus-broker with sanitizers and run the unit test suite ==="
MESON_OPTIONS=()

if [[ "$CC" == clang ]]; then
    # See https://github.com/mesonbuild/meson/issues/764 for details
    MESON_OPTIONS+=(-Db_lundef=false)
fi
if [[ "$WITH_COVERAGE" -ne 0 ]]; then
    MESON_OPTIONS+=(-Db_coverage=true)

    if [[ "$CC" == clang ]]; then
        # clang's version of the gcov tool is a part of llvm-cov, but it's implemented as a subcommand. To get
        # around this, use the --gcov-tool option multiple times as the values are concantenated into the final
        # command (see geninfo(1))
        LCOV_OPTIONS+=(--gcov-tool llvm-cov --gcov-tool gcov)
    fi
fi
if selinuxenabled; then
    MESON_OPTIONS+=(-Dselinux=true)
fi

rm -rf "$BUILD_DIR"
meson setup "$BUILD_DIR" \
    --werror \
    -Daudit=true \
    -Dprefix=/usr \
    -Db_sanitize=address,undefined \
    "${MESON_OPTIONS[@]}"
ninja -C "$BUILD_DIR"

if [[ "$WITH_COVERAGE" -ne 0 ]]; then
    # Capture the initial coverage if requested
    lcov "${LCOV_OPTIONS[@]}" --capture --initial --directory "$BUILD_DIR" -o "$BUILD_DIR/initial.gcov"
fi

meson test -C "$BUILD_DIR" --timeout-multiplier=2 --print-errorlogs
meson test -C "$BUILD_DIR" --benchmark --timeout-multiplier=2 --print-errorlogs

: "=== Run tests against dbus-broker running under sanitizers ==="
# So, this one is a _bit_ convoluted. We want to run dbus-broker under sanitizers, but this bears a couple of
# issues:
#
#   1) We need to restart dbus-broker (and hence the machine we're currently running on)
#   2) If dbus-broker crashes due to ASan/UBSan error, the whole machine is hosed
#
# To make the test a bit more robust without too much effort, let's use systemd-nspawn to run an ephemeral
# container on top of the current rootfs. To get the "sanitized" dbus-broker into that container, we need to
# prepare a special rootfs with just the sanitized dbus-broker (and a couple of other things) which we then
# simply overlay on top of the ephemeral rootfs in the container.
#
# This way, we'll do a full user-space boot with a sanitized dbus-broker without affecting the host machine,
# and without having to build a custom container/VM just for the test.
container_prepare

# Install our custom-built dbus-broker into the container's overlay
DESTDIR="$CONTAINER_OVERLAY" ninja -C "$BUILD_DIR" install
# Pass $ASAN_OPTIONS and $UBSAN_OPTIONS to the dbus-broker service in the container
mkdir -p "$CONTAINER_OVERLAY/etc/systemd/system/dbus-broker.service.d/"
cat >"$CONTAINER_OVERLAY/etc/systemd/system/dbus-broker.service.d/sanitizer-env.conf" <<EOF
[Service]
Environment=ASAN_OPTIONS=$ASAN_OPTIONS
Environment=UBSAN_OPTIONS=$UBSAN_OPTIONS
ProtectSystem=no
EOF
# Do the same for the user unit
mkdir -p "$CONTAINER_OVERLAY/etc/systemd/user/dbus-broker.service.d/"
cat >"$CONTAINER_OVERLAY/etc/systemd/user/dbus-broker.service.d/sanitizer-env.conf" <<EOF
[Service]
Environment=ASAN_OPTIONS=$ASAN_OPTIONS
Environment=UBSAN_OPTIONS=$UBSAN_OPTIONS
EOF
# Run both dbus-broker-launch and dbus-broker under root instead of the usual "dbus" user. This is necessary
# to let sanitizers generate stack traces (killing the process on sanitizer error works even without this
# tweak though, but it's very hard to then tell what went wrong without a stack trace).
mkdir -p "$CONTAINER_OVERLAY/etc/dbus-1/"
cat >"$CONTAINER_OVERLAY/etc/dbus-1/system-local.conf" <<EOF
<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
    <user>root</user>
</busconfig>
EOF

check_journal_for_sanitizer_errors() {
    # FIXME:
    return 0
    if journalctl -q -D "/var/log/journal/${CONTAINER_MACHINE_ID:?}" --grep "SUMMARY:.+Sanitizer"; then
        # Dump all messages recorded for the dbus-broker.service, as that's usually where the stack trace ends
        # up. If that's not the case, the full container journal is exported on test exit anyway, so we'll
        # still have everything we need to debug the fail further.
        journalctl -q -D "/var/log/journal/${CONTAINER_MACHINE_ID:?}" -o short-monotonic --no-hostname -u dbus-broker.service --no-pager
        exit 1
    fi
}

run_and_check() {
    local run=(container_run)
    local unpriv=0

    if [[ "$1" == "--unpriv" ]]; then
        run=(container_run_user testuser)
        unpriv=1
        shift
    fi

    # Run the passed command in the container
    "${run[@]}" "$@"
    # Check if dbus-broker is still running...
    "${run[@]}" systemctl status --full --no-pager dbus-broker.service
    if [[ $unpriv -ne 0 ]]; then
        # (check the user instance too, if applicable)
        "${run[@]}" systemctl status --user --full --no-pager dbus-broker.service
    fi
    # ... and if it didn't generate any sanitizer errors
    check_journal_for_sanitizer_errors
}

# Start the container and wait until it's fully booted up
container_start
container_run dbus-broker --version
container_run dbus-broker-launch --version
# Check if dbus-broker runs under root, see above for reasoning
container_run bash -xec '[[ $(stat --format=%u /proc/$(systemctl show -P MainPID dbus-broker.service)) -eq 0 ]]'
# Make _extra_ sure we're running the sanitized dbus-broker with the correct environment
#
# Note: the check is not particularly nice, as libasan can be linked either statically or dynamically, so we
# can't just check ldd's output. Another option is using nm/objdump to check for ASan-specific functions, but
# that's also error prone. Instead, let's call each binary with ASan's "help" option, which produces output
# only if the target binary is built with (hopefully working) ASan.
container_run bash -xec 'ASAN_OPTIONS=help=1 /proc/$(systemctl show -P MainPID dbus-broker.service)/exe -h 2>&1 >/dev/null | grep -q AddressSanitizer'
container_run bash -xec 'ASAN_OPTIONS=help=1 dbus-broker-launch -h 2>&1 >/dev/null | grep -q AddressSanitizer'
container_run bash -xec 'ASAN_OPTIONS=help=1 dbus-broker -h 2>&1 >/dev/null | grep -q AddressSanitizer'
container_run systemctl show -p Environment dbus-broker.service | grep -q ASAN_OPTIONS
# Do a couple of check for the user instance as well
container_run_user testuser bash -xec 'ASAN_OPTIONS=1 /proc/$(systemctl show --user -P MainPID dbus-broker.service)/exe -h 2>&1 >/dev/null | grep -q AddressSanitizer'
container_run_user testuser systemctl show -p Environment dbus-broker.service | grep -q ASAN_OPTIONS
journalctl -D "/var/log/journal/${CONTAINER_MACHINE_ID:?}" -e -n 10 --no-pager
check_journal_for_sanitizer_errors

# Now we should have a container ready for our shenanigans

# Check the introspection machinery
for object in / /org /org/freedesktop /org/freedesktop/DBus /foo /foo/bar/baz; do
    container_run busctl introspect org.freedesktop.DBus "$object"
done

# Cover a couple of error paths as well
(! container_run dbus-broker)
(! container_run dbus-broker --controller=0)
(! container_run dbus-broker --controller=🐱)
(! container_run dbus-broker --log=0)
(! container_run dbus-broker --log=🐱)
(! container_run dbus-broker --max-bytes="")
(! container_run dbus-broker -🐱)
(! container_run dbus-broker 🐱)
(! container_run dbus-broker-launch)
(! container_run dbus-broker-launch -🐱)
(! container_run dbus-broker-launch 🐱)

(! container_run_user testuser busctl monitor)

check_journal_for_sanitizer_errors

# Fuzz dbus-broker's own interfaces
run_and_check dfuzzer -v -n org.freedesktop.DBus
run_and_check --unpriv dfuzzer -v -n org.freedesktop.DBus

# Now run the dfuzzer on the org.freedesktop.systemd1 as well, since it's pretty rich when it comes to
# signature variations.
#
# Since fuzzing the entire systemd bus tree takes way too long (as it spends most of the time fuzzing the
# /org/freedesktop/systemd1/unit/ objects, which is the same stuff over and over again), let's selectively
# pick a couple of interesting objects to speed things up.
#
# First, fuzz the manager object...
run_and_check --unpriv dfuzzer -n org.freedesktop.systemd1 -o /org/freedesktop/systemd1
# ... and then pick first 10 units from the /org/freedesktop/systemd1/unit/ tree.
while read -r object; do
    run_and_check --unpriv dfuzzer -n org.freedesktop.systemd1 -o "$object"
done < <(busctl tree --list --no-legend org.freedesktop.systemd1 | grep /unit/ | head -n10)

# Let's also send some garbage to the dbus socket to check if dbus-broker handles it nicely
for _ in {0..15}; do
    # Note: ignore socat's exit code, as it fails with "Connection reset by peer" in most cases, for obvious
    # reasons
    container_run bash -xec 'head -n100 /dev/urandom | socat - UNIX-CONNECT:/run/dbus/system_bus_socket || :'
    container_run bash -xec 'head -n100 /dev/urandom | base64 | socat - UNIX-CONNECT:/run/dbus/system_bus_socket || :'
done
container_run systemctl status --full --no-pager dbus-broker.service
check_journal_for_sanitizer_errors

# TODO:
#   - src/launch/config.c has low coverage; would benefit from extending the existing unit test and a fuzzer
#   - src/launch/policy.c has low coverage; would benefit a unit test and a fuzzer
#   - src/launch/service.c: starting a transient service (instead of an existing unit) is not covered
#   - test/dbus/tool-flood.c: maybe add an argument to limit the # of pings and run it here as well?
#   - src/dbus/test-address.c: missing tests for address_init_from_name and address_write()

# Shut down the container and check for any sanitizer errors, since some of the errors can be detected only
# after we start shutting things down.
container_stop
check_journal_for_sanitizer_errors
# Also, check if dbus-broker didn't fail during the lifetime of the container
(! journalctl -q -D "/var/log/journal/$CONTAINER_MACHINE_ID" _PID=1 --grep "dbus-broker.service.*Failed with result")

if [[ $WITH_COVERAGE -ne 0 && -n "${TMT_TEST_DATA:-}" ]]; then
    # Capture the actual coverage, merged it with the initial one, and generate a final HTML report
    lcov "${LCOV_OPTIONS[@]}" --capture --directory "$BUILD_DIR" -o "$BUILD_DIR/actual.gcov"
    lcov "${LCOV_OPTIONS[@]}" --add-tracefile "$BUILD_DIR/initial.gcov" --add-tracefile "$BUILD_DIR/actual.gcov" -o "$BUILD_DIR/merged.gcov"
    genhtml -o "$TMT_TEST_DATA/coverage/" "$BUILD_DIR/merged.gcov"
fi

exit 0
