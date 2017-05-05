#pragma once

/*
 * Socket Listener
 */

#include <c-list.h>
#include <c-macro.h>
#include <stdlib.h>
#include "util/dispatch.h"

typedef struct Bus Bus;
typedef struct Listener Listener;

struct Listener {
        Bus *bus;
        int socket_fd;
        DispatchFile socket_file;
        CList bus_link;
        CList peer_list;
};

#define LISTENER_NULL(_x) {                                             \
                .socket_fd = -1,                                        \
                .socket_file = DISPATCH_FILE_NULL((_x).socket_file),    \
                .bus_link = C_LIST_INIT((_x).bus_link),                 \
                .peer_list = C_LIST_INIT((_x).peer_list),               \
        }

int listener_init_with_fd(Listener *listener,
                          Bus *bus,
                          DispatchFn dispatch_fn,
                          int socket_fd);
void listener_deinit(Listener *listener);
int listener_accept(Listener *listener);

C_DEFINE_CLEANUP(Listener *, listener_deinit);
