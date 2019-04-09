/*
 * Miscellaneous Helpers
 *
 * These are helpers that have no other obvious home.
 */

#include <c-stdaux.h>
#include <grp.h>
#include <stdlib.h>
#include <unistd.h>
#include "util/error.h"
#include "util/misc.h"

/**
 * util_umul64_saturating() - saturating multiplication
 * @a:                  first operand
 * @b:                  second operand
 *
 * This calculates @a multiplied by @b and returns the result. In case of an
 * integer overflow, it will return `UINT64_MAX`.
 *
 * Return: The saturated result is returned.
 */
uint64_t util_umul64_saturating(uint64_t a, uint64_t b) {
        uint64_t res;

        if (__builtin_mul_overflow(a, b, &res))
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
