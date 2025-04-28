/*
 * Nanosecond Time Management
 *
 * This module provides time management utilities around the `nsec_t` type,
 * which carries time information encoded as nano-seconds since a
 * clock-specific EPOCH. The clock source is not encoded at all but must be
 * transferred via other means, if necessary.
 *
 * A 64-bit unsigned integer is used as backing data type. This can store
 * seconds up to:
 *
 *     2^64 / 1_000_000_000 = 18,446,744,073.7
 *
 * or years up to:
 *
 *     2^64 / 1_000_000_000 / 60 / 60 / 24 / 365 ~= 584
 *
 * This is a suitable range for time-keeping in most situations. If any
 * calendar, or other date-related functionality is needed, this type might not
 * be suitable.
 */

#include <c-stdaux.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include "util/nsec.h"

#define NSEC_PER_SEC UINT64_C(1000000000)

/* Similar to `intprops.h`: provides `_MAX` for signed types without it. */
#define NSEC_TIME_T_MAX                                                 \
        ((time_t)(                                                      \
                (UINTMAX_C(1) << ((sizeof(time_t) << 3) - 1)) - 1)      \
        )

/**
 * nsec_now() - get the current time in nanoseconds
 * @clock:      clock to query
 *
 * Read the current time and return it in nanoseconds. The clock must be
 * specified by the caller. Only non-fallible clocks can be used with this
 * function.
 *
 * Return: the timestamp in nano seconds.
 */
nsec_t nsec_now(clockid_t clock) {
        struct timespec ts;
        int r;

        r = clock_gettime(clock, &ts);
        c_assert(r >= 0);

        return (uint64_t)ts.tv_sec * NSEC_PER_SEC + (uint64_t)ts.tv_nsec;
}

/**
 * nsec_sleep() - pause execution
 * @clock:      clock to use for time keeping
 * @until:      absolute timeout of the pause
 *
 * Pause exeuction until the absolute timeout specified by `until` is reached.
 * The timeout must be relative to the clock specified by `clock`.
 *
 * The operation is automatically repeated, if it is interrupted by a signal.
 */
void nsec_sleep(clockid_t clock, nsec_t until) {
        struct timespec ts;
        uint64_t tv_sec, tv_nsec;
        int r;

        tv_sec = until / NSEC_PER_SEC;
        tv_nsec = until % NSEC_PER_SEC;

        c_assert(tv_sec <= NSEC_TIME_T_MAX);

        ts.tv_sec = (time_t)tv_sec;
        ts.tv_nsec = (long)tv_nsec;

        do {
                /* Note that `clock_nanosleep()` does not use `errno`! */
                r = clock_nanosleep(clock, TIMER_ABSTIME, &ts, NULL);
                c_assert(r == 0 || r == EINTR);
        } while (r == EINTR);
}
