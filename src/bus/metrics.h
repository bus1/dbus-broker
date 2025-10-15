#pragma once

/*
 * Metrics Listener
 */

#include <c-list.h>
#include <c-stdaux.h>
#include <stdlib.h>
#include "util/dispatch.h"

typedef struct Bus Bus;
typedef struct Metrics Metrics;
typedef struct MetricsClient MetricsClient;

struct MetricsClient {
        CList metrics_link;
        int socket_fd;
        DispatchFile socket_file;
        uint8_t *buffer;
        size_t i_buffer;
        size_t n_buffer;
};

struct Metrics {
        Bus *bus;
        int socket_fd;
        DispatchFile socket_file;
        CList client_list;
};

#define METRICS_NULL(_x) {                                                      \
                .socket_fd = -1,                                                \
                .socket_file = DISPATCH_FILE_NULL((_x).socket_file),            \
                .client_list = C_LIST_INIT((_x).client_list),                   \
        }

int metrics_init_with_fd(Metrics *metrics,
                         Bus *bus,
                         DispatchContext *dispatcher,
                         int socket_fd);
void metrics_deinit(Metrics *metrics);

C_DEFINE_CLEANUP(Metrics *, metrics_deinit);
