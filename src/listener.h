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

int listener_new_with_fd(Listener **listenerp, Bus *bus, int socket_fd);
Listener *listener_free(Listener *free);

C_DEFINE_CLEANUP(Listener *, listener_free);
