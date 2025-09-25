#pragma once

/*
 * Metrics Listener
 */

#include <c-stdaux.h>
#include <stdlib.h>
#include "util/dispatch.h"

typedef struct Bus Bus;
typedef struct Metrics Metrics;

struct Metrics {
        Bus *bus;
        int socket_fd;
        DispatchFile socket_file;
};

#define METRICS_NULL(_x) {                                                      \
                .socket_fd = -1,                                                \
                .socket_file = DISPATCH_FILE_NULL((_x).socket_file),            \
        }

int metrics_init_with_fd(Metrics *metrics,
                         Bus *bus,
                         DispatchContext *dispatcher,
                         int socket_fd);
void metrics_deinit(Metrics *metrics);

C_DEFINE_CLEANUP(Metrics *, metrics_deinit);
