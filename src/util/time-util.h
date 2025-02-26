#pragma once

/*
 * Time Utilities
 */

#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <time.h>

typedef uint64_t usec_t;
typedef uint64_t nsec_t;

#define PRI_USEC PRIu64
#define USEC_FMT "%" PRI_USEC

#define USEC_INFINITY ((usec_t) UINT64_MAX)

#define NSEC_PER_USEC ((nsec_t) 1000ULL)
#define USEC_PER_SEC  ((usec_t) 1000000ULL)

usec_t now(clockid_t clock);

usec_t timespec_load(const struct timespec *ts);
