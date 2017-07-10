/*
 * Test Infrastructure around dbus-broker
 */

#include <c-macro.h>
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

static int util_broker_sigchld(sd_event_source *source, const siginfo_t *si, void *userdata) {
        return sd_event_exit(sd_event_source_get_event(source),
                             (si->si_code == CLD_EXITED) ? si->si_status : EXIT_FAILURE);
}

void util_fork_broker(sd_bus **busp, sd_event *event, int listener_fd) {
        _c_cleanup_(sd_bus_unrefp) sd_bus *bus = NULL;
        _c_cleanup_(c_freep) char *fdstr = NULL;
        int r, pair[2];
        pid_t pid;

        r = socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, pair);
        assert(r >= 0);

        pid = fork();
        assert(pid >= 0);
        c_close(pair[!!pid]);

        if (pid == 0) {
                /* clear the FD_CLOEXEC flag */
                r = fcntl(pair[1], F_SETFD, 0);
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

        r = sd_event_add_child(event, NULL, pid, WEXITED, util_broker_sigchld, NULL);
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

        r = sd_bus_call_method(bus,
                               NULL,
                               "/org/bus1/DBus/Broker",
                               "org.bus1.DBus.Broker",
                               "AddListener",
                               NULL,
                               NULL,
                               "ohs",
                               "/org/bus1/DBus/Listener/0",
                               listener_fd,
                               NULL);
        assert(r >= 0);

        *busp = bus;
        bus = NULL;
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

        free(broker);

        return NULL;
}

static void *util_broker_thread(void *userdata) {
        _c_cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _c_cleanup_(sd_bus_unrefp) sd_bus *bus = NULL;
        Broker *broker = userdata;
        int r;

        util_event_new(&event);
        util_fork_broker(&bus, event, broker->listener_fd);

        r = sd_event_loop(event);
        assert(r >= 0);

        broker->listener_fd = -1;
        return (void *)(uintptr_t)r;
}

void util_broker_spawn(Broker *broker) {
        sigset_t signew, sigold;
        int r;

        assert(broker->listener_fd < 0);

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

        pthread_sigmask(SIG_SETMASK, &sigold, NULL);
}

void util_broker_terminate(Broker *broker) {
        void *value;
        int r;

        assert(broker->listener_fd >= 0);

        r = pthread_kill(broker->thread, SIGUSR1);
        assert(!r);

        r = pthread_join(broker->thread, &value);
        assert(!r);
        assert(!value);

        assert(broker->listener_fd < 0);
}

void util_broker_connect(Broker *broker, sd_bus **busp) {
        _c_cleanup_(sd_bus_unrefp) sd_bus *bus = NULL;
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
