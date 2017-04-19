#pragma once

/*
 * In-process bus for testing
 */

#include <c-macro.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "bus.h"

static inline void *test_run_bus(void *userdata) {
        Bus *bus;
        int fd = (intptr_t)userdata, r;

        r = bus_new(&bus, fd, 1024, 1024, 1024, 1024, 1024);
        assert(r >= 0);

        r = bus_run(bus);
        assert(r == 0);

        peer_registry_flush(&bus->peers);

        bus_free(bus);

        close(fd);
        return NULL;
}

static inline pthread_t test_spawn_bus(struct sockaddr_un *addressp, socklen_t *addrlenp) {
        struct sockaddr_un address = {
                .sun_family = AF_UNIX,
                /* .sun_path[0] = '\0', */
        };
        socklen_t addrlen = sizeof(address);
        _c_cleanup_(c_closep) int fd = -1;
        pthread_t thread;
        int r;

        fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        assert(fd >= 0);

        r = bind(fd, (struct sockaddr*) &address, offsetof(struct sockaddr_un, sun_path));
        assert(r >= 0);

        r = getsockname(fd, (struct sockaddr*) &address, &addrlen);
        assert(r >= 0);

        r = listen(fd, 256);
        assert(r >= 0);

        r = pthread_create(&thread, NULL, test_run_bus, (void*)(intptr_t)fd);
        assert(r >= 0);

        fd = -1;
        *addrlenp = addrlen;
        *addressp = address;

        return thread;
}
