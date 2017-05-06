#pragma once

/*
 * Forked off broker + controller pair for testing
 */

#include <c-macro.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <systemd/sd-bus.h>
#include <systemd/sd-event.h>
#include "util/error.h"

static inline void *test_run_controller(void *userdata) {
        int listener_fd = (intptr_t)userdata, r;
        _c_cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _c_cleanup_(sd_bus_unrefp) sd_bus *bus = NULL;
        int pair[2];
        pid_t pid;
        sigset_t signew, sigold;

        r = socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, pair);
        assert(r >= 0);

        pid = fork();
        assert(pid >= 0);
        if (pid == 0) { /* child */
                char controller_fdstr[C_DECIMAL_MAX(int) + 1];

                c_close(pair[0]);

                /* clear the FD_CLOEXEC flag */
                r = fcntl(pair[1], F_SETFD, 0);
                assert(r >= 0);

                r = snprintf(controller_fdstr, sizeof(controller_fdstr), "%d", pair[1]);
                assert(r >= 0 && (size_t)r < sizeof(controller_fdstr));

                r = execl("./src/dbus-broker", "./src/dbus-broker", "--verbose", "--controller", controller_fdstr, (char *)NULL);
                assert(r >= 0); /* should never return */
        }

        c_close(pair[1]);

        r = sd_event_default(&event);
        assert(r >= 0);

        sigemptyset(&signew);
        sigaddset(&signew, SIGTERM);
        sigaddset(&signew, SIGINT);
        sigprocmask(SIG_BLOCK, &signew, &sigold);

        r = sd_event_add_signal(event, NULL, SIGTERM, NULL, NULL);
        assert(r >= 0);
        r = sd_event_add_signal(event, NULL, SIGINT, NULL, NULL);
        assert(r >= 0);

        r = sd_bus_new(&bus);
        assert(r >= 0);

        r = sd_bus_attach_event(bus, event, SD_EVENT_PRIORITY_NORMAL);
        assert(r >= 0);

        /* consumes the fd */
        r = sd_bus_set_fd(bus, pair[0], pair[0]);
        assert(r >= 0);

        r = sd_bus_start(bus);
        assert(r >= 0);

        r = sd_bus_call_method(bus, NULL, "/org/bus1/DBus/Controller", "org.bus1.DBus.Controller", "AddListener", NULL, NULL,
                               "oh", "/org/bus1/DBus/Listener/Main", listener_fd);
        assert(r >= 0);

        r = sd_event_loop(event);
        assert(r >= 0);

        sigprocmask(SIG_SETMASK, &sigold, NULL);

        return NULL;
}

static inline pthread_t test_spawn_broker(struct sockaddr_un *addressp, socklen_t *addrlenp) {
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

        r = pthread_create(&thread, NULL, test_run_controller, (void*)(intptr_t)fd);
        assert(r >= 0);

        fd = -1;
        *addrlenp = addrlen;
        *addressp = address;

        return thread;
}
