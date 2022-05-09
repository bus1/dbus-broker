/*
 * Bus AppArmor Fallback Helpers
 *
 * This fallback is used when libapparmor is not available, and is meant to be
 * functionally equivalent to util/apparmor.c in case AppArmor is disabled.
 *
 * See util/apparmor.c for details.
 */

#include <c-stdaux.h>
#include <stdio.h>
#include <stdlib.h>
#include "util/apparmor.h"

/**
 * bus_apparmor_is_enabled() - checks if AppArmor is currently enabled
 * @enabled:            return argument telling if AppArmor is enabled
 *
 * If the AppArmor module is not loaded, or AppArmor is disabled in the
 * kernel, set @enabledp to 'false', otherwise set it to 'true'.
 *
 * Returns: 0 if check succeeded, or negative error code on failure.
 */
int bus_apparmor_is_enabled(bool *enabledp) {
        *enabledp = false;
        return 0;
}

/**
 * bus_apparmor_dbus_supported() - check for apparmor dbus support
 * @supported:            return argument telling if AppArmor DBus is supported
 *
 * If the AppArmor module is not loaded, or AppArmor does not support DBus,
 * set @supportedp to 'false', otherwise set it to 'true'.
 *
 * Returns: 0 if check succeeded, or negative error code on failure.
 */
int bus_apparmor_dbus_supported(bool *supportedp) {
        *supportedp = false;
        return 0;
}
