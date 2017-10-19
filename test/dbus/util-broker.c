/*
 * Test Infrastructure around dbus-broker
 */

#include <c-macro.h>
#include <c-syscall.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <systemd/sd-bus.h>
#include <systemd/sd-event.h>
#include "util-broker.h"

void util_event_new(sd_event **eventp) {
        _c_cleanup_(sd_event_unrefp) sd_event *event = NULL;
        sigset_t sigold;
        int r;

        r = sd_event_default(&event);
        assert(r >= 0);

        pthread_sigmask(SIG_BLOCK, NULL, &sigold);
        assert(sigismember(&sigold, SIGCHLD) == 1);
        assert(sigismember(&sigold, SIGUSR1) == 1);

        r = sd_event_add_signal(event, NULL, SIGUSR1, NULL, (void *)(uintptr_t)0);
        assert(r >= 0);

        *eventp = event;
        event = NULL;
}

static int util_event_sigchld(sd_event_source *source, const siginfo_t *si, void *userdata) {
        return sd_event_exit(sd_event_source_get_event(source),
                             (si->si_code == CLD_EXITED) ? si->si_status : EXIT_FAILURE);
}

#define POLICY_T_BATCH                                                          \
                "bt"                                                            \
                "a(btbs)"                                                       \
                "a(btssssub)"                                                   \
                "a(btssssub)"

#define POLICY_T                                                                \
                "(" POLICY_T_BATCH ")"                                          \
                "a(u(" POLICY_T_BATCH "))"                                      \
                "a(u(" POLICY_T_BATCH "))"                                      \
                "a(ss)"

static int util_append_policy(sd_bus_message *m) {
        int r;

        r = sd_bus_message_open_container(m, 'v', "(" POLICY_T ")");
        assert(r >= 0);

        r = sd_bus_message_open_container(m, 'r', POLICY_T);
        assert(r >= 0);

        /* default batch */
        {
                r = sd_bus_message_open_container(m, 'r', POLICY_T_BATCH);
                assert(r >= 0);

                /*
                 * Default test policy:
                 *  - allow all connections
                 *  - allow everyone to own names
                 *  - allow all sends
                 *  - allow all recvs
                 */
                r = sd_bus_message_append(m,
                                          "bt" "a(btbs)" "a(btssssub)" "a(btssssub)",
                                          true, UINT64_C(1),
                                          1, true, UINT64_C(1), true, "",
                                          1, true, UINT64_C(1), "", "", "", "", 0, false,
                                          1, true, UINT64_C(1), "", "", "", "", 0, false);

                r = sd_bus_message_close_container(m);
                assert(r >= 0);
        }

        /* per-uid batches */
        {
                r = sd_bus_message_open_container(m, 'a', "(u(" POLICY_T_BATCH "))");
                assert(r >= 0);

                r = sd_bus_message_close_container(m);
                assert(r >= 0);
        }

        /* per-gid batches */
        {
                r = sd_bus_message_open_container(m, 'a', "(u(" POLICY_T_BATCH "))");
                assert(r >= 0);

                r = sd_bus_message_close_container(m);
                assert(r >= 0);
        }

        /* empty SELinux policy */
        {
                r = sd_bus_message_open_container(m, 'a', "(ss)");
                assert(r >= 0);

                r = sd_bus_message_close_container(m);
                assert(r >= 0);
        }

        r = sd_bus_message_close_container(m);
        assert(r >= 0);

        r = sd_bus_message_close_container(m);
        assert(r >= 0);

        return 0;
}

void util_fork_broker(sd_bus **busp, sd_event *event, int listener_fd, pid_t *pidp) {
        _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _c_cleanup_(sd_bus_message_unrefp) sd_bus_message *message = NULL, *message2 = NULL;
        _c_cleanup_(c_freep) char *fdstr = NULL;
        int r, pair[2];
        pid_t pid;

        r = socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, pair);
        assert(r >= 0);

        /* the broker reports the controller as its pid */
        if (pidp)
                *pidp = getpid();

        pid = fork();
        assert(pid >= 0);
        c_close(pair[!!pid]);

        if (pid == 0) {
                /* clear the FD_CLOEXEC flag */
                r = fcntl(pair[1], F_GETFD);
                assert(r >= 0);
                r = fcntl(pair[1], F_SETFD, r & ~FD_CLOEXEC);
                assert(r >= 0);

                r = asprintf(&fdstr, "%d", pair[1]);
                assert(r >= 0);

                r = execl("./src/dbus-broker",
                          "./src/dbus-broker",
                          "--verbose",
                          "--controller", fdstr,
                          (char *)NULL);
                /* execl(2) only returns on error */
                assert(r >= 0);
                abort();
        }

        r = sd_event_add_child(event, NULL, pid, WEXITED, util_event_sigchld, NULL);
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

        r = sd_bus_message_new_method_call(bus,
                                           &message,
                                           NULL,
                                           "/org/bus1/DBus/Broker",
                                           "org.bus1.DBus.Broker",
                                           "AddListener");
        assert(r >= 0);

        r = sd_bus_message_append(message,
                                  "oh",
                                  "/org/bus1/DBus/Listener/0",
                                  listener_fd);
        assert(r >= 0);

        r = util_append_policy(message);
        assert(r >= 0);

        r = sd_bus_call(bus, message, -1, NULL, NULL);
        assert(r >= 0);

        r = sd_bus_message_new_method_call(bus,
                                           &message2,
                                           NULL,
                                           "/org/bus1/DBus/Listener/0",
                                           "org.bus1.DBus.Listener",
                                           "SetPolicy");
        assert(r >= 0);

        r = util_append_policy(message2);
        assert(r >= 0);

        r = sd_bus_call(bus, message2, -1, NULL, NULL);
        assert(r >= 0);

        *busp = bus;
        bus = NULL;
}

void util_fork_daemon(sd_event *event, int pipe_fd, pid_t *pidp) {
        static const char *config =
                "<!DOCTYPE busconfig PUBLIC "
                "\"-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN\" "
                "\"http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd\">\n"
                "<busconfig>\n"
                "  <auth>EXTERNAL</auth>\n"
                "  <listen>unix:tmpdir=/tmp</listen>\n"
                "  <policy context=\"default\">\n"
                "    <allow user=\"*\"/>\n"
                "    <allow send_destination=\"*\" eavesdrop=\"true\"/>\n"
                "    <allow receive_sender=\"*\" eavesdrop=\"true\"/>\n"
                "    <allow own=\"*\"/>\n"
                "  </policy>\n"
                "</busconfig>\n";
        _c_cleanup_(c_freep) char *fdstr = NULL, *path = NULL;
        const char *bin;
        ssize_t n;
        int r, fd;
        pid_t pid;

        pid = fork();
        assert(pid >= 0);

        if (pid == 0) {
                /* make dbus-daemon(1) die if we do */
                r = prctl(PR_SET_PDEATHSIG, SIGTERM);
                assert(!r);

                /* clear the FD_CLOEXEC flag */
                r = fcntl(pipe_fd, F_GETFD);
                assert(r >= 0);
                r = fcntl(pipe_fd, F_SETFD, r & ~FD_CLOEXEC);
                assert(r >= 0);

                /* write config into memfd (don't set MFD_CLOEXEC) */
                fd = c_syscall_memfd_create("dbus-daemon-config-file", 0);
                assert(fd >= 0);
                n = write(fd, config, strlen(config));
                assert(n == (ssize_t)strlen(config));

                /* prepare argv parameters */
                r = asprintf(&path, "--config-file=/proc/self/fd/%d", fd);
                assert(r >= 0);
                r = asprintf(&fdstr, "--print-address=%d", pipe_fd);
                assert(r >= 0);

                /* exec dbus-daemon */
                bin = getenv("DBUS_BROKER_TEST_DAEMON") ?: "/usr/bin/dbus-daemon";
                r = execl(bin,
                          bin,
                          path,
                          fdstr,
                          (char *)NULL);
                /* execl(3) only returns on failure */
                assert(r >= 0);
                abort();
        }

        /* remember the daemon's pid */
        if (pidp)
                *pidp = pid;

        /* monitor the daemon process */
        r = sd_event_add_child(event, NULL, pid, WEXITED, util_event_sigchld, NULL);
        assert(r >= 0);
}

void util_broker_new(Broker **brokerp) {
        _c_cleanup_(util_broker_freep) Broker *broker = NULL;

        broker = calloc(1, sizeof(*broker));
        assert(broker);

        *broker = (Broker)BROKER_NULL;

        *brokerp = broker;
        broker = NULL;
}

Broker *util_broker_free(Broker *broker) {
        if (!broker)
                return NULL;

        assert(broker->listener_fd < 0);
        assert(broker->pipe_fds[0] < 0);
        assert(broker->pipe_fds[1] < 0);

        free(broker);

        return NULL;
}

static void *util_broker_thread(void *userdata) {
        _c_cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        Broker *broker = userdata;
        int r;

        assert(broker->pipe_fds[0] >= 0);
        assert(broker->pipe_fds[1] >= 0);

        util_event_new(&event);

        if (broker->listener_fd >= 0) {
                util_fork_broker(&bus, event, broker->listener_fd, &broker->pid);
        } else {
                assert(broker->listener_fd < 0);
                util_fork_daemon(event, broker->pipe_fds[1], &broker->pid);
        }

        broker->pipe_fds[1] = c_close(broker->pipe_fds[1]);

        r = sd_event_loop(event);
        assert(r >= 0);

        broker->listener_fd = -1;
        broker->pipe_fds[0] = c_close(broker->pipe_fds[0]);
        return (void *)(uintptr_t)r;
}

void util_broker_spawn(Broker *broker) {
        char buffer[PIPE_BUF + 1] = {};
        sigset_t signew, sigold;
        ssize_t n;
        char *e;
        int r;

        assert(broker->listener_fd < 0);
        assert(broker->pipe_fds[0] < 0);
        assert(broker->pipe_fds[1] < 0);

        /*
         * Lets make sure we exit if our parent does. We are a test-runner, so
         * this should be enforced by our environment, but sadly it isn't. So
         * lets use this hack to enforce it everywhere and cleanup properly.
         */
        r = prctl(PR_SET_PDEATHSIG, SIGTERM);
        assert(!r);

        /*
         * SIGCHLD signal delivery is non-deterministic in thread-groups.
         * Hence, we must block SIGCHLD in *all* threads if we want to reliably
         * catch broker-deaths via sd_event_add_child(). Lets just enforce this
         * here.
         */
        sigemptyset(&signew);
        sigaddset(&signew, SIGCHLD);
        pthread_sigmask(SIG_BLOCK, &signew, NULL);

        sigemptyset(&signew);
        sigaddset(&signew, SIGUSR1);
        pthread_sigmask(SIG_BLOCK, &signew, &sigold);

        /*
         * Create a pipe object that we inherit into the forked daemon. In case
         * of dbus-daemon(1) it is actually used to retrieve data from it. In
         * case of dbus-broker, we use it to block until our child called
         * exec() (as a synchronization primitive).
         */
        r = pipe2(broker->pipe_fds, O_CLOEXEC | O_DIRECT);
        assert(r >= 0);

        if (getenv("DBUS_BROKER_TEST_DAEMON")) {
                /*
                 * Our pipe is passed to a forked dbus-daemon(1). It will
                 * write its picked address to the pipe, which we then remember
                 * in the broker object.
                 * We use this both as synchronization primitive, and as a way
                 * to retrieve the unix-address from dbus-daemon(1).
                 */

                r = pthread_create(&broker->thread, NULL, util_broker_thread, broker);
                assert(r >= 0);

                /* read address from pipe */
                n = read(broker->pipe_fds[0], buffer, sizeof(buffer) - 1);
                assert(n >= 0 && n < (ssize_t)sizeof(buffer));
                assert(!strncmp(buffer, "unix:abstract=", strlen("unix:abstract=")));

                /* copy over the path into @broker */
                broker->address.sun_path[0] = '\0';
                e = memccpy(broker->address.sun_path + 1,
                            buffer + strlen("unix:abstract="),
                            ',',
                            sizeof(broker->address.sun_path) - 2);
                assert(e);
                --e;
                assert(*e == ',');
                broker->n_address = e - (char *)&broker->address;
        } else {
                /*
                 * Create listener socket, let the kernel pick a random address
                 * and remember it in @broker. Spawn a thread, which will then
                 * run and babysit the broker.
                 */

                broker->listener_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
                assert(broker->listener_fd >= 0);

                r = bind(broker->listener_fd, (struct sockaddr *)&broker->address, offsetof(struct sockaddr_un, sun_path));
                assert(r >= 0);

                r = getsockname(broker->listener_fd, (struct sockaddr *)&broker->address, &broker->n_address);
                assert(r >= 0);

                r = listen(broker->listener_fd, 256);
                assert(r >= 0);

                r = pthread_create(&broker->thread, NULL, util_broker_thread, broker);
                assert(r >= 0);

                /* block until we get EOF, so we know the broker was exec'ed */
                r = read(broker->pipe_fds[0], buffer, sizeof(buffer) - 1);
                assert(!r);
        }

        pthread_sigmask(SIG_SETMASK, &sigold, NULL);
}

void util_broker_terminate(Broker *broker) {
        void *value;
        int r;

        assert(broker->listener_fd >= 0 || broker->pipe_fds[0] >= 0);

        r = pthread_kill(broker->thread, SIGUSR1);
        assert(!r);

        r = pthread_join(broker->thread, &value);
        assert(!r);
        assert(!value);

        assert(broker->listener_fd < 0);
        assert(broker->pipe_fds[0] < 0);
}

void util_broker_connect_fd(Broker *broker, int *fdp) {
        _c_cleanup_(c_closep) int fd = -1;
        int r;

        fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        assert(fd >= 0);

        r = connect(fd, (struct sockaddr *)&broker->address, broker->n_address);
        assert(r >= 0);

        *fdp = fd;
        fd = -1;
}

void util_broker_connect_raw(Broker *broker, sd_bus **busp) {
        _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _c_cleanup_(c_closep) int fd = -1;
        int r;

        fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        assert(fd >= 0);

        r = connect(fd, (struct sockaddr *)&broker->address, broker->n_address);
        assert(r >= 0);

        r = sd_bus_new(&bus);
        assert(r >= 0);

        /* consumes @fd */
        r = sd_bus_set_fd(bus, fd, fd);
        fd = -1;
        assert(r >= 0);

        r = sd_bus_start(bus);
        assert(r >= 0);

        *busp = bus;
        bus = NULL;
}

void util_broker_connect(Broker *broker, sd_bus **busp) {
        _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _c_cleanup_(c_closep) int fd = -1;
        int r;

        fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        assert(fd >= 0);

        r = connect(fd, (struct sockaddr *)&broker->address, broker->n_address);
        assert(r >= 0);

        r = sd_bus_new(&bus);
        assert(r >= 0);

        /* consumes @fd */
        r = sd_bus_set_fd(bus, fd, fd);
        fd = -1;
        assert(r >= 0);

        r = sd_bus_set_bus_client(bus, true);
        assert(r >= 0);

        r = sd_bus_start(bus);
        assert(r >= 0);

        *busp = bus;
        bus = NULL;
}
