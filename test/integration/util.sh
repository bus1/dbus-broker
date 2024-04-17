# vi: set sw=4 ts=4 et tw=110:
# shellcheck shell=bash disable=SC2155

CONTAINER_NAME=""
CONTAINER_MACHINE_ID=""
CONTAINER_OVERLAY=""

__COREDUMPCTL_TS=""

# Prepare a systemd-nspawn container so we can test (and restart) dbus-broker safely without risking the
# underlying test machine.
#
# This function prepares a lightweight nspawn container that reuses the rootfs of the underlying test machine
# to run dbus-broker under various tools (or a completely custom-built dbus-broker version) without risking
# damage to the underlying test machine. The container simply combines the /etc and /usr directories from the
# host with our own additions using overlayfs, which is then bind-mounted into the container, so we do a full
# user-space boot without needing to build a custom image or restart the underlying test machine itself.
#
# The function exports/modifies three environment variables:
#   - $CONTAINER_NAME - container name that can be used to identify the machine in machinectl calls (or in
#                       direct calls to the systemd-nspawn@.service template)
#   - $CONTAINER_MACHINE_ID - machine ID of the container, which can be used to locate the container's journal
#                             under /var/log/journal/$CONTAINER_MACHINE_ID
#   - $CONTAINER_OVERLAY - upper layer of the container overlayfs that can be used to add additional bits into
#                          the final container (note that only /etc and /usr subdirectores from this direcory
#                          are used)
#
# Once the container is ready, it can be booted up using container_start(). To execute commands inside the
# container, container_run() and container_run_user() might come in handy.
container_prepare() {
    # Export a couple of env variables which can be used to track/alter the container
    CONTAINER_NAME="dbus-broker-container-$RANDOM"
    CONTAINER_MACHINE_ID="$(systemd-id128 new)"
    CONTAINER_OVERLAY="/var/lib/machines/$CONTAINER_NAME"

    # Switch SELinux to permissive (if enabled), so it doesn't interfere with the container shenanigans below.
    setenforce 0 || :
    # We need persistent journal for the systemd-nspawn --link= stuff
    mkdir -p /var/log/journal
    journalctl --flush

    # Prepare the nspawn container service
    mkdir -p "/var/lib/machines/$CONTAINER_NAME"
    # Notes:
    #   - with systemd v256+ this can be replaced by systemctl edit --stdin --runtime ..., and the
    #     mkdir/daemon-reload can be dropped
    #   - systemd-nspawn can't overlay the whole rootfs (/), so we need to cherry-pick a couple of subdirectories
    #     we're interested in (in this case it's pretty simple, since dbus-broker installs everything under /usr,
    #     and we need /etc with our dbus-broker.service override)
    #   - since the whole container is ephemeral, use --link-journal=host, so the journal directory for the
    #     container is created on the _host_ under /var/log/journal/<machine-id> and bind-mounted into the
    #     container; that way we can fetch the container journal for debugging even if something goes horribly
    #     wrong
    mkdir -p "/run/systemd/system/systemd-nspawn@$CONTAINER_NAME.service.d"
    cat >"/run/systemd/system/systemd-nspawn@$CONTAINER_NAME.service.d/override.conf" <<EOF
    [Service]
# We'll handle the coredumps on the host instead
CoredumpReceive=no
ExecStart=
ExecStart=systemd-nspawn --quiet --network-veth --keep-unit --machine=%i --boot \
                         --link-journal=host \
                         --volatile=yes \
                         --directory=/ \
                         --uuid=$CONTAINER_MACHINE_ID \
                         --hostname=$CONTAINER_NAME \
                         --overlay=/etc:$CONTAINER_OVERLAY/etc:/etc \
                         --overlay-ro=/usr:$CONTAINER_OVERLAY/usr:/usr \
                         ${BUILD_DIR:+"--bind=$BUILD_DIR:$BUILD_DIR"}
EOF
    systemctl daemon-reload


    # Prepare the nspawn container overlay
    mkdir "$CONTAINER_OVERLAY"/{etc,usr}/
    # Let systemd-nspawn propagate the machine ID and hostname we passed it
    : >"$CONTAINER_OVERLAY/etc/machine-id"
    : >"$CONTAINER_OVERLAY/etc/hostname"
    # Create a non-root user, so we can test session bus stuff as well
    mkdir -p "$CONTAINER_OVERLAY/etc/sysusers.d/"
    cat >"$CONTAINER_OVERLAY/etc/sysusers.d/testuser.conf" <<EOF
u testuser - "Test User" /home/testuser
EOF
}

# Start the container created by container_prepare() and wait until it boots.
container_start() {
    if [[ -z "$CONTAINER_NAME" ]]; then
        echo >&2 "No container to start (missing call to container_prepare()?)"
        return 1
    fi

    machinectl start "$CONTAINER_NAME"
    timeout --foreground 30s bash -ec "until systemd-run -M $CONTAINER_NAME --wait --pipe true; do sleep .5; done"
    # is-system-running returns > 0 if the system is running in degraded mode, but we don't care about that, we
    # just need to wait until the bootup is finished
    container_run systemctl is-system-running -q --wait || :
    container_run systemctl status --full --no-pager dbus-broker.service
    container_run_user testuser systemctl status --user --full --no-pager dbus-broker.service
}

container_stop() {
    # Note: machinectl poweroff doesn't wait until the container shuts down completely, stop stop the service
    #       behind it instead which does wait
    systemctl stop "systemd-nspawn@${CONTAINER_NAME:?}.service"
}

# Run a command in a container as a root.
container_run() {
    systemd-run -M "${CONTAINER_NAME:?}" --wait --pipe "$@"
}

# Same as above, but run the command under a specific user.
container_run_user() {
    local user="${1:?}"
    shift

    systemd-run -M "$user@${CONTAINER_NAME:?}" --user --wait --pipe "$@"
}

container_destroy() {
    if [[ -z "$CONTAINER_NAME" ]]; then
        return 0
    fi

    if systemctl -q is-active "systemd-nspawn@$CONTAINER_NAME.service"; then
        container_stop
    fi

    # Export the container journal and sanitizer logs if $TMT_TEST_DATA is set, either by TMT directly or
    # manually.
    if [[ -n "${TMT_TEST_DATA:-}" ]]; then
        mkdir -p "$TMT_TEST_DATA"
        journalctl -D "/var/log/journal/$CONTAINER_MACHINE_ID" -o short-monotonic >"$TMT_TEST_DATA/$CONTAINER_NAME.log"
    fi

    rm -rf "/var/lib/machines/$CONTAINER_NAME"
    rm -rf "/var/log/journal/$CONTAINER_MACHINE_ID"
    rm -rf "/run/systemd/system/systemd-nspawn@$CONTAINER_NAME.service.d"
    systemctl daemon-reload
}

coredumpctl_init() {
    local ec

    if ! systemctl start systemd-coredump.socket; then
        echo >&2 "Failed to start systemd-coredump.socket"
        return 1
    fi

    # Note: coredumpctl returns 1 when no coredumps are found
    coredumpctl --since=now >/dev/null && ec=0 || ec=$?
    if [[ $ec -ne 1 ]]; then
        echo >&2 "coredumpctl is not in operative state"
        return 1
    fi

    # Set the internal coredumpctl timestamp, so we consider coredumps only from now on
    __COREDUMPCTL_TS="$(date +"%Y-%m-%d %H:%M:%S")"

    return 0
}

# Attempt to dump info about relevant coredumps using the coredumpctl utility.
#
# Returns:
#   0 when no coredumps were found, 1 otherwise
coredumpctl_collect() (
    set +ex

    local args=(-q --no-legend --no-pager)
    local tempfile="$(mktemp)"

    # Register a cleanup handler
    #
    # Note: since this function is a technically a subshell, RETURN trap won't work here
    # shellcheck disable=SC2064
    trap "rm -f '$tempfile'" EXIT

    if [[ -n "$__COREDUMPCTL_TS" ]]; then
        args+=(--since "$__COREDUMPCTL_TS")
    fi

    if ! coredumpctl "${args[@]}" -F COREDUMP_EXE >"$tempfile"; then
        echo "No relevant coredumps found"
        return 0
    fi

    # For each unique executable path call 'coredumpctl info' to get the stack trace and other useful info
    while read -r path; do
        local exe
        local gdb_cmd="set print pretty on\nbt full"

        coredumpctl "${args[@]}" info "$path"
        # Make sure we use the built binaries for getting gdb trace
        #
        # This is relevant mainly for the sanitizers run, where we don't install the just built revision, so
        # `coredumpctl debug` pulls in a local binary instead of the built one, which produces useless
        # results.
        if [[ -v BUILD_DIR && -d $BUILD_DIR ]]; then
            # The build directory layout of dbus-broker is not flat, so we need to find the binary first
            exe="$(find "$BUILD_DIR" -executable -name "${path##*/}" | head -n1)"
            if [[ -n "$exe" ]]; then
                gdb_cmd="file $exe\nthread apply all bt\n$gdb_cmd"
            fi
        fi

        # Attempt to get a full stack trace for the first occurrence of the given executable path
        if gdb -v >/dev/null; then
            echo -e "\n"
            echo "Trying to run gdb with '$gdb_cmd' for '$path'"
            echo -e "$gdb_cmd" | coredumpctl "${args[@]}" debug "$path"
            echo -e "\n"
        fi
    done < <(sort -u "$tempfile")

    return 1
)
