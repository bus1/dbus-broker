#pragma once

/*
 * Metrics Helper
 */

#include <c-stdaux.h>
#include <stdlib.h>
#include <time.h>

#define METRICS_TIMESTAMP_INVALID ((uint64_t) -1)

typedef struct Metrics Metrics;

struct Metrics {
        uint64_t count;
        uint64_t sum;
        uint64_t minimum;
        uint64_t maximum;
        uint64_t average;

        /* internal state */
        clockid_t id;
        uint64_t timestamp;
        uint64_t sum_of_squares;
};

#define METRICS_INIT(_id) {                                     \
                .minimum = (uint64_t) -1,                       \
                .id = (_id),                                    \
                .timestamp = METRICS_TIMESTAMP_INVALID,         \
        }

void metrics_init(Metrics *metrics, clockid_t id);
void metrics_deinit(Metrics *metrics);

uint64_t metrics_get_time(Metrics *metrics);
void metrics_sample_add(Metrics *metrics, uint64_t timestamp);

void metrics_sample_start(Metrics *metrics);
void metrics_sample_end(Metrics *metrics);

double metrics_read_standard_deviation(Metrics *metrics);
