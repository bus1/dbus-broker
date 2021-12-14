/*
 * Bus AppArmor Helpers
 *
 * AppArmor support is not implemented upstream in dbus-broker, as the
 * required kernel infrastructure is not yet upstream in the kernel.
 *
 * We just do the bare minimum of refusing to start if AppArmor is
 * configured to be required, and to warn if support is enabled in
 * the kernel, and AppArmor is configured to be enabled by the
 * applicable policy.
 */

#include <c-stdaux.h>
#include <stdlib.h>
#include <stdio.h>
#include "util/apparmor.h"
#include "util/error.h"

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
        _c_cleanup_(c_fclosep) FILE *f = NULL;
        char buffer[LINE_MAX] = {};
        bool enabled;

        f = fopen("/sys/module/apparmor/parameters/enabled", "re");
        if (f) {
                errno = 0;
                if (!fgets(buffer, sizeof(buffer), f)) {
                        if (ferror(f))
                                return error_origin(-c_errno());
                }

                switch (buffer[0]) {
                        case 'Y':
                                enabled = true;
                                break;
                        case 'N':
                                enabled = false;
                                break;
                        default:
                                return error_origin(-EIO);
                }
        } else if (errno == ENOENT) {
                enabled = false;
        } else {
                return error_origin(-errno);
        }

        *enabledp = enabled;
        return 0;
}

/**
 * bus_apparmor_dbus_supported() - checks if Kernel has AppArmor support for DBus
 * @supported:            return argument telling if AppArmor DBus is supported
 *
 * If the AppArmor module is not loaded, or AppArmor does not support DBus,
 * set @supportedp to 'false', otherwise set it to 'true'.
 *
 * Returns: 0 if check succeeded, or negative error code on failure.
 */
int bus_apparmor_dbus_supported(bool *supportedp) {
        _c_cleanup_(c_fclosep) FILE *f = NULL;
        char buffer[LINE_MAX] = {};
        bool supported;

        f = fopen("/sys/kernel/security/apparmor/features/dbus/mask", "re");
        if (f) {
                errno = 0;
                if (!fgets(buffer, sizeof(buffer), f)) {
                        if (ferror(f) && errno != EINVAL)
                                return errno ? error_origin(-errno) : error_origin(-ENOTRECOVERABLE);
                }

                if (strstr(buffer, "acquire") && strstr(buffer, "send") && strstr(buffer, "receive"))
                        supported = true;
                else
                        supported = false;
        } else if (errno == ENOENT) {
                supported = false;
        } else {
                return error_origin(-errno);
        }

        *supportedp = supported;
        return 0;
}
