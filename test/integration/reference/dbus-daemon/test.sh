#!/bin/bash
# vi: set sw=4 ts=4 et tw=110:

set -eu
set -o pipefail

mapfile -t REFERENCE_TESTS < <(find /usr/lib/dbus-broker/tests/dbus -type f)

if [[ ${#REFERENCE_TESTS[@]} -eq 0 ]]; then
    echo >&2 "No reference tests found, this is most likely an error"
    exit 1
fi

if ! DBUS_DAEMON_BIN="$(command -v dbus-daemon)"; then
    echo >&2 "Missing dbus-daemon binary"
    exit 1
fi

if ! DBUS_BROKER_BIN="$(command -v dbus-broker)"; then
    echo >&2 "Missing dbus-broker binary"
    exit 1
fi

run_tests() {
    local ec

    echo "DBUS_BROKER_TEST_DAEMON = ${DBUS_BROKER_TEST_DAEMON:-unset}"
    echo "DBUS_BROKER_TEST_BROKER = ${DBUS_BROKER_TEST_BROKER:-unset}"

    for test in "${REFERENCE_TESTS[@]}"; do
        echo "--- $test BEGIN ---"
        # FIXME: bench-message takes forever with dbus-daemon
        #
        # Just to give an idea: on my machine this test takes over 13 minutes (!) with dbus-daemon
        # compared to just ~32 seconds with dbus-broker.
        if [[ -n "${DBUS_BROKER_TEST_DAEMON:-}" && "$test" =~ /bench-message$ ]]; then
            echo "Skipping bench-message with dbus-daemon, as it's _very_ slow"
            continue
        fi

        time "$test" && ec=0 || ec=$?
        case "$ec" in
            0)
                echo "Test $test PASSED"
                ;;
            77)
                echo "Test $test was SKIPPED"
                ;;
            *)
                echo "Test $test FAILED with exit code $ec"
                return "$ec"
        esac
        echo "--- $test END ---"
        echo
    done
}

echo "=== Run reference tests against dbus-daemon ==="
"$DBUS_DAEMON_BIN" --version
DBUS_BROKER_TEST_DAEMON="$DBUS_DAEMON_BIN" run_tests

echo

echo "=== Run reference tests against dbus-broker ==="
"$DBUS_BROKER_BIN" --version
DBUS_BROKER_TEST_BROKER="$DBUS_BROKER_BIN" run_tests
