#pragma once

/*
 * In-process bus for testing
 */

#include <c-macro.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include "bus.h"
#include "util/error.h"

static int test_dispatch_signals(DispatchFile *file, uint32_t events) {
        struct signalfd_siginfo si;
        ssize_t l;

        assert(events == EPOLLIN);

        l = read(file->fd, &si, sizeof(si));
        if (l < 0)
                return error_origin(-errno);

        assert(l == sizeof(si));

        return DISPATCH_E_EXIT;
}

static inline void *test_run_bus(void *userdata) {
        Bus *bus;
        Listener *listener;
        int fd = (intptr_t)userdata, r;
        sigset_t signew, sigold;
        _c_cleanup_(c_closep) int signals_fd = -1;
        DispatchFile signals_file;

        r = bus_new(&bus, 1024, 1024, 1024, 1024, 1024);
        assert(r >= 0);

        r = listener_new_with_fd(&listener, bus, fd);
        assert(r >= 0);

        sigemptyset(&signew);
        sigaddset(&signew, SIGTERM);
        sigaddset(&signew, SIGINT);

        signals_fd = signalfd(-1, &signew, SFD_CLOEXEC | SFD_NONBLOCK);
        assert(signals_fd >= 0);

        r = dispatch_file_init(&signals_file, &bus->dispatcher, test_dispatch_signals, signals_fd, EPOLLIN);
        assert(r >= 0);

        dispatch_file_select(&signals_file, EPOLLIN);

        sigprocmask(SIG_BLOCK, &signew, &sigold);

        do {
                r = dispatch_context_dispatch(&bus->dispatcher);
                if (r != DISPATCH_E_EXIT && r != DISPATCH_E_FAILURE)
                        r = error_fold(r);
        } while (!r);

        sigprocmask(SIG_SETMASK, &sigold, NULL);

        dispatch_file_deinit(&signals_file);
        peer_registry_flush(&bus->peers);
        listener_free(listener);
        bus_free(bus);

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
