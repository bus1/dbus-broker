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

static int bus_accept(DispatchFile *file, uint32_t events) {
        Bus *bus = c_container_of(file, Bus, accept_file);
        _c_cleanup_(c_closep) int fd = -1;
        _c_cleanup_(peer_freep) Peer *peer = NULL;
        int r;

        if (!(events & EPOLLIN))
                return 0;

        fd = accept4(bus->accept_fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (fd < 0) {
                if (errno == EAGAIN) {
                        dispatch_file_clear(file, EPOLLIN);
                        return 0;
                } else if (errno == ECONNRESET || errno == EPERM) {
                        /* ignore pending errors on the new socket */
                        return 0;
                }
                return error_origin(-errno);
        }

        r = peer_new(&peer, bus, fd);
        if (r)
                return error_fold(r);
        fd = -1;

        r = peer_start(peer);
        if (r)
                return error_fold(r);

        peer = NULL;
        return 0;
}

int bus_new(Bus **busp,
            int accept_fd,
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

        bus->ready_list = (CList)C_LIST_INIT(bus->ready_list);
        bus->hup_list = (CList)C_LIST_INIT(bus->hup_list);
        bus->accept_fd = accept_fd;
        bus->signal_fd = signal_fd;
        signal_fd = -1;
        match_registry_init(&bus->wildcard_matches);
        match_registry_init(&bus->driver_matches);
        /* XXX: initialize guid with random data */
        name_registry_init(&bus->names);
        user_registry_init(&bus->users, max_bytes, max_fds, max_peers, max_names, max_matches);
        peer_registry_init(&bus->peers);
        bus->dispatcher = (DispatchContext)DISPATCH_CONTEXT_NULL;
        bus->accept_file = (DispatchFile)DISPATCH_FILE_NULL(bus->accept_file);

        r = dispatch_context_init(&bus->dispatcher);
        if (r)
                return error_fold(r);

        r = dispatch_file_init(&bus->accept_file,
                               &bus->dispatcher,
                               &bus->ready_list,
                               bus_accept,
                               bus->accept_fd,
                               EPOLLIN);
        if (r)
                return error_fold(r);

        dispatch_file_select(&bus->accept_file, EPOLLIN);

        r = dispatch_file_init(&bus->signal_file,
                               &bus->dispatcher,
                               &bus->ready_list,
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

        dispatch_file_deinit(&bus->signal_file);
        dispatch_file_deinit(&bus->accept_file);

        assert(c_list_is_empty(&bus->hup_list));
        assert(c_list_is_empty(&bus->ready_list));

        dispatch_context_deinit(&bus->dispatcher);
        peer_registry_deinit(&bus->peers);
        user_registry_deinit(&bus->users);
        name_registry_deinit(&bus->names);
        match_registry_deinit(&bus->driver_matches);
        match_registry_deinit(&bus->wildcard_matches);

        free(bus);

        return NULL;
}

static int bus_dispatch(Bus *bus) {
        DispatchFile *file;
        CList list = C_LIST_INIT(list);
        int r = 0;

        while ((file = c_list_first_entry(&bus->ready_list, DispatchFile, ready_link))) {
                c_list_unlink(&file->ready_link);
                c_list_link_tail(&list, &file->ready_link);

                r = dispatch_file_call(file);
                if (r)
                        break;
        }

        c_list_splice(&bus->ready_list, &list);

        return error_trace(r);
}

int bus_run(Bus *bus) {
        sigset_t mask;
        int r;

        sigemptyset(&mask);
        sigaddset(&mask, SIGTERM);
        sigaddset(&mask, SIGINT);
        sigprocmask(SIG_BLOCK, &mask, NULL);

        for (;;) {
                r = dispatch_context_poll(&bus->dispatcher, c_list_is_empty(&bus->ready_list) ? -1 : 0);
                if (r)
                        goto exit;

                r = bus_dispatch(bus);
                if (r)
                        break;
        }

        if (r == DISPATCH_E_EXIT)
                r = 0;
        else
                r = error_fold(r);

exit:
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
