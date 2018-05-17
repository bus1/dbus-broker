/*
 * Miscellaneous Helpers
 *
 * These are helpers that have no other obvious home.
 */

#include <c-macro.h>
#include <grp.h>
#include <stdlib.h>
#include <unistd.h>
#include "util/error.h"
#include "util/misc.h"

int util_drop_permissions(uint32_t uid, uint32_t gid) {
        int r;

        /* for compatibility to dbus-daemon, this must be non-fatal */
        setgroups(0, NULL);

        r = setgid(gid);
        if (r < 0)
                return error_origin(-errno);

        r = setuid(uid);
        if (r < 0)
                return error_origin(-errno);

        return 0;
}
