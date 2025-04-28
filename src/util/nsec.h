#pragma once

/*
 * Nanosecond Time Management
 */

#include <c-stdaux.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>

typedef uint64_t nsec_t;

#define NSEC_PRI PRIu64

/* nsec */

nsec_t nsec_now(clockid_t clock);
void nsec_sleep(clockid_t clock, nsec_t until);

/* inline helpers */

static inline uint64_t nsec_to_usec(nsec_t t) {
        return t / 1000;
}
