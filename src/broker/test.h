#pragma once

/*
 * Forked off broker + controller pair for testing
 */

#include <c-macro.h>
#include <c-syscall.h>
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
        _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int pair[2];
        pid_t pid;
        sigset_t signew, sigold;

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

        r = sd_bus_new(&bus);
        assert(r >= 0);

        r = sd_bus_attach_event(bus, event, SD_EVENT_PRIORITY_NORMAL);
        assert(r >= 0);

        /* consumes the fd */
        r = sd_bus_set_fd(bus, pair[0], pair[0]);
        assert(r >= 0);

        r = sd_bus_start(bus);
        assert(r >= 0);

        r = sd_bus_call_method(bus, NULL, "/org/bus1/DBus/Broker", "org.bus1.DBus.Broker", "AddListener", NULL, NULL,
                               "ohs", "/org/bus1/DBus/Listener/0", listener_fd, "");
        assert(r >= 0);

        r = sd_event_loop(event);
        assert(r >= 0);

        sigprocmask(SIG_SETMASK, &sigold, NULL);

        return NULL;
}


static inline pid_t test_spawn_daemon(struct sockaddr_un *addressp, socklen_t *addrlenp) {
        char buffer[PIPE_BUF];
        pid_t pid;
        char *e;
        int pipe[2], r;
        ssize_t len;

        r = pipe2(pipe, O_CLOEXEC | O_DIRECT);
        assert(r >= 0);

        pid = fork();
        assert(pid >= 0);
        if (pid == 0) { /* child */
                char pipe_fdstr[strlen("--print-address=") + C_DECIMAL_MAX(int) + 1],
                     config_filename[strlen("--config-file=/proc/self/fd/") + C_DECIMAL_MAX(int) + 1];
                static const char *config = \
"<!DOCTYPE busconfig PUBLIC \"-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN\" \"http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd\">\n" \
"<busconfig>\n"                                                 \
"  <auth>EXTERNAL</auth>\n"                                     \
"  <listen>unix:tmpdir=/tmp</listen>\n"                         \
"  <policy context=\"default\">\n"                              \
"    <allow user=\"*\"/>\n"                                     \
"    <allow send_destination=\"*\" eavesdrop=\"true\"/>\n"      \
"    <allow eavesdrop=\"true\"/>\n"                             \
"    <allow own=\"*\"/>\n"                                      \
"  </policy>\n"                                                 \
"</busconfig>\n";
                int fd;

                c_close(pipe[0]);

                /* clear the FD_CLOEXEC flag */
                r = fcntl(pipe[1], F_SETFD, 0);
                assert(r >= 0);

                r = snprintf(pipe_fdstr, sizeof(pipe_fdstr), "--print-address=%d", pipe[1]);
                assert(r >= 0 && (size_t)r < sizeof(pipe_fdstr));

                fd = c_syscall_memfd_create("dbus-daemon-config-file", 0);
                assert(fd >= 0);

                r = write(fd, config, strlen(config));
                assert(r >= 0);

                r = snprintf(config_filename, sizeof(config_filename), "--config-file=/proc/self/fd/%d", fd);
                assert(r >= 0 && (size_t)r < sizeof(config_filename));

                r = execl("/usr/bin/dbus-daemon", "/usr/bin/dbus-daemon", config_filename, pipe_fdstr, (char *)NULL);
                assert(r >= 0); /* should never return */
        }

        c_close(pipe[1]);

        len = read(pipe[0], buffer, sizeof(buffer));
        assert(len >= 0);
        assert(strncmp(buffer, "unix:abstract=", strlen("unix:abstract=")) == 0);

        addressp->sun_family = AF_UNIX;
        addressp->sun_path[0] = '\0';
        e = memccpy(addressp->sun_path + 1, buffer + strlen("unix:abstract="), ',', sizeof(addressp->sun_path) - 2);
        assert(e);
        --e;
        assert(*e == ',');

        *addrlenp = e - (char*)addressp;

        c_close(pipe[0]);

        return pid;
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
