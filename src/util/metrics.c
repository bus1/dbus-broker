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

#include <c-stdaux.h>
#include <math.h>
#include <stdlib.h>
#include <time.h>
#include "util/metrics.h"

void metrics_init(Metrics *metrics, clockid_t id) {
        *metrics = (Metrics)METRICS_INIT(id);
}

void metrics_deinit(Metrics *metrics) {
        c_assert(metrics->timestamp == METRICS_TIMESTAMP_INVALID);
        metrics_init(metrics, metrics->id);
}

/**
 * metrics_get_time() - get the current thread CPU time
 *
 * Read the current thread CPU time to be used to record samples.
 *
 * Return: the timestamp in nano seconds.
 */
uint64_t metrics_get_time(Metrics *metrics) {
        struct timespec ts;
        int r;

        r = clock_gettime(metrics->id, &ts);
        c_assert(r >= 0);

        return ts.tv_sec * UINT64_C(1000000000) + ts.tv_nsec;
}

/**
 * metrics_sample_add() - add one sample
 * @metrics:            object to operate on
 * @timestamp:          time the sample was started
 *
 * Update the internal state with a new sample, started at @timestamp
 * and ending at the time the function is called.
 */
void metrics_sample_add(Metrics *metrics, uint64_t timestamp) {
        uint64_t sample, average_old;

        sample = metrics_get_time(metrics) - timestamp;

        metrics->count ++;
        metrics->sum += sample;

        average_old = metrics->average;
        metrics->average = metrics->sum / metrics->count;
        metrics->sum_of_squares += (sample - average_old) * (sample - metrics->average);

        if (metrics->minimum > sample)
                metrics->minimum = sample;

        if (metrics->maximum < sample)
                metrics->maximum = sample;
}

/**
 * metrics_sample_start() - start a new sample
 * @metrics:            object to operate on
 *
 * Start a new sample by recording the current timestamp, verifying that
 * a sample is not currently running.
 */
void metrics_sample_start(Metrics *metrics) {
        c_assert(metrics->timestamp == METRICS_TIMESTAMP_INVALID);
        metrics->timestamp = metrics_get_time(metrics);
}

/**
 * metrics_sample_end() - end a running sample
 * @metrics:            object to operate on
 *
 * End a currently running sample, and update the internal state.
 */
void metrics_sample_end(Metrics *metrics) {
        c_assert(metrics->timestamp != METRICS_TIMESTAMP_INVALID);

        metrics_sample_add(metrics, metrics->timestamp);

        metrics->timestamp = METRICS_TIMESTAMP_INVALID;
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
