/*
 * Metrics Helper
 *
 * See `Note on a Method for Calculating Corrected Sums of Squares and Products' by
 * W. P. Welford, 1962.
 */

#include <c-macro.h>
#include <math.h>
#include <stdlib.h>
#include <time.h>
#include "util/metrics.h"

void metrics_init(Metrics *metrics) {
        *metrics = (Metrics)METRICS_INIT;
}

void metrics_deinit(Metrics *metrics) {
        assert(!metrics->timestamp);
        metrics_init(metrics);
}

static uint64_t metrics_get_time(void) {
        struct timespec ts;
        int r;

        r = clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts);
        assert(r >= 0);

        return ts.tv_sec * UINT64_C(1000000000) + ts.tv_nsec;
}

void metrics_sample_start(Metrics *metrics) {
        assert(!metrics->timestamp);
        metrics->timestamp = metrics_get_time();
}

void metrics_sample_end(Metrics *metrics) {
        uint64_t sample, average_old;

        assert(metrics->timestamp);

        sample = metrics_get_time() - metrics->timestamp;

        metrics->count ++;
        metrics->sum += sample;

        average_old = metrics->average;
        metrics->average = metrics->sum / metrics->count;
        metrics->sum_of_squares += (sample - average_old) * (sample - metrics->average);

        if (metrics->minimum > sample)
                metrics->minimum = sample;

        if (metrics->maximum < sample)
                metrics->maximum = sample;

        metrics->timestamp = 0;
}

double metrics_read_standard_deviation(Metrics *metrics) {
        if (!metrics->count)
                return 0;

        return sqrt(metrics->sum_of_squares / metrics->count);
}
