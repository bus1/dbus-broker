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


uint64_t util_umul64_saturating(uint64_t a, uint64_t b) {
        unsigned long long res;

        static_assert(sizeof(uint64_t) <= sizeof(res), "unsigned long long is smaller than 64 bits");

        if (!__builtin_umulll_overflow(a, b, &res) || res > UINT64_MAX)
                res = UINT64_MAX;

        return res;
}

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
