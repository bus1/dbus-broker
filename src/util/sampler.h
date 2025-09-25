#pragma once

/*
 * Sampler Helper
 */

#include <c-stdaux.h>
#include <stdlib.h>
#include <time.h>

#define SAMPLER_TIMESTAMP_INVALID ((uint64_t) -1)

typedef struct Sampler Sampler;

struct Sampler {
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

#define SAMPLER_INIT(_id) {                                     \
                .minimum = (uint64_t) -1,                       \
                .id = (_id),                                    \
                .timestamp = SAMPLER_TIMESTAMP_INVALID,         \
        }

void sampler_init(Sampler *sampler, clockid_t id);
void sampler_deinit(Sampler *sampler);

uint64_t sampler_get_time(Sampler *sampler);
void sampler_sample_add(Sampler *sampler, uint64_t timestamp);

void sampler_sample_start(Sampler *sampler);
void sampler_sample_end(Sampler *sampler);

double sampler_read_standard_deviation(Sampler *sampler);
