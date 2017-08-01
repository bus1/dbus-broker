#pragma once

/*
 * Metrics Helper
 */

#include <c-macro.h>
#include <stdlib.h>

typedef struct Metrics Metrics;

struct Metrics {
        uint64_t count;
        uint64_t sum;
        uint64_t minimum;
        uint64_t maximum;
        uint64_t average;

        /* internal state */
        uint64_t timestamp;
        uint64_t sum_of_squares;
};

#define METRICS_INIT {                          \
                .minimum = (uint64_t) -1,       \
        }

void metrics_init(Metrics *metrics);
void metrics_deinit(Metrics *metrics);

uint64_t metrics_get_time(void);
void metrics_sample_add(Metrics *metrics, uint64_t timestamp);

void metrics_sample_start(Metrics *metrics);
void metrics_sample_end(Metrics *metrics);

double metrics_read_standard_deviation(Metrics *metrics);
