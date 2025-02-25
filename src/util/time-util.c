#include <sys/types.h>
#include <time.h>

#include "util/error.h"
#include "util/time-util.h"

usec_t now(clockid_t clock_id) {
        struct timespec ts;
        int r;

        r = clock_gettime(clock_id, &ts);
        if (r != 0) {
            // Set errno and log.
            error_origin(r);
            return USEC_INFINITY;
        }

        return timespec_load(&ts);
}

usec_t timespec_load(const struct timespec *ts) {
        assert(ts);

        if (ts->tv_sec < 0 || ts->tv_nsec < 0)
                return USEC_INFINITY;

        if ((usec_t) ts->tv_sec > (UINT64_MAX - (ts->tv_nsec / NSEC_PER_USEC)) / USEC_PER_SEC)
                return USEC_INFINITY;

        return
                (usec_t) ts->tv_sec * USEC_PER_SEC +
                (usec_t) ts->tv_nsec / NSEC_PER_USEC;
}
