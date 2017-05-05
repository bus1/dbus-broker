/*
 * Bus Context
 */

#include <c-macro.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include "bus.h"
#include "dbus/unique-name.h"
#include "driver.h"
#include "match.h"
#include "name.h"
#include "user.h"
#include "util/dispatch.h"
#include "util/error.h"

static int bus_signal(DispatchFile *file, uint32_t events) {
        Bus *bus = c_container_of(file, Bus, signal_file);
        struct signalfd_siginfo fdsi;
        ssize_t size;

        if (!(events & EPOLLIN))
                return 0;

        size = read(bus->signal_fd, &fdsi, sizeof(fdsi));
        if (size < 0)
                return -errno;

        assert(size == sizeof(fdsi));
        assert(fdsi.ssi_signo == SIGTERM || fdsi.ssi_signo == SIGINT);

        return DISPATCH_E_EXIT;
}

int bus_new(Bus **busp,
            unsigned int max_bytes,
            unsigned int max_fds,
            unsigned int max_peers,
            unsigned int max_names,
            unsigned int max_matches) {
        _c_cleanup_(bus_freep) Bus *bus = NULL;
        _c_cleanup_(c_closep) int signal_fd = -1;
        sigset_t mask;
        int r;

        sigemptyset(&mask);
        sigaddset(&mask, SIGTERM);
        sigaddset(&mask, SIGINT);
        signal_fd = signalfd(-1, &mask, SFD_NONBLOCK|SFD_CLOEXEC);
        if (signal_fd < 0)
                return error_origin(-errno);

        bus = calloc(1, sizeof(*bus));
        if (!bus)
                return error_origin(-ENOMEM);

        bus->listener_list = (CList)C_LIST_INIT(bus->listener_list);
        bus->signal_fd = signal_fd;
        signal_fd = -1;
        match_registry_init(&bus->wildcard_matches);
        match_registry_init(&bus->driver_matches);
        /* XXX: initialize guid with random data */
        name_registry_init(&bus->names);
        user_registry_init(&bus->users, max_bytes, max_fds, max_peers, max_names, max_matches);
        peer_registry_init(&bus->peers);
        bus->dispatcher = (DispatchContext)DISPATCH_CONTEXT_NULL(bus->dispatcher);

        r = dispatch_context_init(&bus->dispatcher);
        if (r)
                return error_fold(r);

        r = dispatch_file_init(&bus->signal_file,
                               &bus->dispatcher,
                               bus_signal,
                               bus->signal_fd,
                               EPOLLIN);
        if (r)
                return error_fold(r);

        dispatch_file_select(&bus->signal_file, EPOLLIN);

        *busp = bus;
        bus = NULL;
        return 0;
}

Bus *bus_free(Bus *bus) {
        if (!bus)
                return NULL;

        assert(c_list_is_empty(&bus->listener_list));

        dispatch_file_deinit(&bus->signal_file);

        dispatch_context_deinit(&bus->dispatcher);
        peer_registry_deinit(&bus->peers);
        user_registry_deinit(&bus->users);
        name_registry_deinit(&bus->names);
        match_registry_deinit(&bus->driver_matches);
        match_registry_deinit(&bus->wildcard_matches);


        free(bus);

        return NULL;
}

int bus_run(Bus *bus) {
        sigset_t mask;
        int r;

        sigemptyset(&mask);
        sigaddset(&mask, SIGTERM);
        sigaddset(&mask, SIGINT);
        sigprocmask(SIG_BLOCK, &mask, NULL);

        do {
                r = dispatch_context_dispatch(&bus->dispatcher);
                if (r == DISPATCH_E_EXIT) {
                        r = 0;
                        break;
                }

                r = error_fold(r);
        } while (!r);

        sigprocmask(SIG_UNBLOCK, &mask, NULL);
        return r;
}

/* XXX: use proper return codes */
Peer *bus_find_peer_by_name(Bus *bus, const char *name) {
        int r;

        if (*name != ':') {
                return name_registry_resolve_name(&bus->names, name);
        } else {
                uint64_t id;

                r = unique_name_to_id(name, &id);
                if (r < 0)
                        return NULL;

                return peer_registry_find_peer(&bus->peers, id);
        }
}
