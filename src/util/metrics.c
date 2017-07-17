/*
 * Metrics Helper
 *
 * The metrics object is used to compute the min/max/avg/std deviation of samples of
 * CPU time, in fixed size and without memory allocations.
 *
 * The values of min/max/avg are meant to be read out of the struct directly, whereas
 * the standard deviation can only be accessed using a helper function (as it is not
 * actually stored directly, but computed on-demand).
 *
 * Only one sample may be active at any point in time, and every sample that is started,
 * must be stopped.
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

/**
 * metrics_sample_start() - start a new sample
 * @metrics:            object to operate on
 *
 * Start a new sample by recording the current timestamp, verifying that
 * a sample is not currently running.
 */
void metrics_sample_start(Metrics *metrics) {
        assert(!metrics->timestamp);
        metrics->timestamp = metrics_get_time();
}

/**
 * metrics_sample_end() - end a running sample
 * @metrics:            object to operate on
 *
 * End a currently running sample, and update the internal state.
 */
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

/**
 * metrics_read_standard_deviation() - read out the current standard deviation
 * @metrics:            objcet to operate on
 *
 * This computes and returns the standard deviation of the samples recorded
 * so far. The standard devitaion is not stored internally, but computed
 * on-demand.
 *
 * If the standard deviation is not defined (no samples were taken), then
 * zero is returned.
 *
 * Return: the standard deviation, or 0 if not defined.
 */
double metrics_read_standard_deviation(Metrics *metrics) {
        if (!metrics->count)
                return 0;

        return sqrt(metrics->sum_of_squares / metrics->count);
}
