/*
 * Bus Context
 */

#include <c-macro.h>
#include <poll.h>
#include <stdlib.h>
#include <sys/socket.h>
#include "bus.h"
#include "dbus-match.h"
#include "dispatch.h"
#include "driver.h"
#include "name.h"
#include "user.h"

static int bus_get_peersec(int fd, char **labelp, size_t *lenp) {
        _c_cleanup_(c_freep) char *label = NULL;
        char *l;
        socklen_t len = 1023;
        int r;

        label = malloc(len + 1);
        if (!label)
                return -ENOMEM;

        for (;;) {
                r = getsockopt(fd, SOL_SOCKET, SO_PEERSEC, &label, &len);
                if (r >= 0) {
                        label[len] = '\0';
                        *lenp = len;
                        *labelp = label;
                        label = NULL;
                        break;
                } else if (errno == ENOPROTOOPT) {
                        *lenp = 0;
                        *labelp = NULL;
                } else if (errno != ERANGE)
                        return -errno;

                l = realloc(label, len + 1);
                if (!l)
                        return -ENOMEM;

                label = l;
        }

        return 0;
}

static int bus_accept(DispatchFile *file, uint32_t events) {
        Bus *bus = c_container_of(file, Bus, accept_file);
        _c_cleanup_(c_closep) int fd = -1;
        _c_cleanup_(user_entry_unrefp) UserEntry *user = NULL;
        _c_cleanup_(peer_freep) Peer *peer = NULL;
        _c_cleanup_(c_freep) char *label = NULL;
        size_t n_label;
        struct ucred ucred;
        socklen_t socklen = sizeof(ucred);
        int r;

        if (!(events & POLLIN))
                return 0;

        fd = accept4(bus->fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (fd < 0) {
                if (errno == EAGAIN) {
                        dispatch_file_clear(file, POLLIN);
                        return 0;
                } else if (errno == ECONNRESET || errno == EPERM) {
                        /* ignore pending errors on the new socket */
                        return 0;
                }
                return -errno;
        }

        r = getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &ucred, &socklen);
        if (r < 0)
                return -errno;

        r = bus_get_peersec(fd, &label, &n_label);
        if (r < 0)
                return r;

        r = peer_new(bus, &peer, fd, ucred.uid, ucred.pid, label, n_label);
        if (r < 0)
                return r;
        fd = -1;
        label = NULL;

        r = peer_start(peer);
        if (r < 0)
                return r;

        peer = NULL;
        return 0;
}

int bus_new(Bus **busp,
            int fd,
            unsigned int max_bytes,
            unsigned int max_fds,
            unsigned int max_peers,
            unsigned int max_names,
            unsigned int max_matches) {
        _c_cleanup_(bus_freep) Bus *bus = NULL;
        int r;

        bus = calloc(1, sizeof(*bus));
        if (!bus)
                return -ENOMEM;

        bus->ready_list = (CList)C_LIST_INIT(bus->ready_list);
        bus->fd = fd;
        dbus_match_registry_init(&bus->matches);
        /* XXX: initialize guid with random data */

        r = name_registry_new(&bus->names);
        if (r < 0)
                return r;

        r = user_registry_new(&bus->users,
                              max_bytes,
                              max_fds,
                              max_peers,
                              max_names,
                              max_matches);
        if (r < 0)
                return r;

        r = dispatch_context_new(&bus->dispatcher);
        if (r < 0)
                return r;

        dispatch_file_init(&bus->accept_file,
                           bus_accept,
                           bus->dispatcher,
                           &bus->ready_list);

        *busp = bus;
        bus = NULL;
        return 0;
}

Bus *bus_free(Bus *bus) {
        if (!bus)
                return NULL;

        assert(!bus->peers.root);
        assert(c_list_is_empty(&bus->ready_list));

        dispatch_file_deinit(&bus->accept_file);
        dispatch_context_free(bus->dispatcher);
        user_registry_free(bus->users);
        name_registry_free(bus->names);
        dbus_match_registry_deinit(&bus->matches);

        free(bus);

        return NULL;
}

int bus_dispatch(Bus *bus) {
        DispatchFile *file, *safe;
        int r;

        c_list_for_each_entry_safe(file, safe, &bus->ready_list, ready_link) {
                r = file->fn(file, file->events);
                if (r < 0)
                        return r;
        }

        return 0;
}

int bus_run(Bus *bus) {
        int r;

        for (;;) {
                r = bus_dispatch(bus);
                if (r < 0)
                        return r;

                r = dispatch_context_poll(bus->dispatcher, -1, NULL);
                if (r < 0)
                        return r;
        }
}

static int peer_compare(CRBTree *tree, void *k, CRBNode *rb) {
        Peer *peer = c_container_of(rb, Peer, rb);
        uint64_t id = *(uint64_t*)k;

        if (peer->id < id)
                return -1;
        if (peer->id > id)
                return 1;

        return 0;
}

void bus_register_peer(Bus *bus, Peer *peer) {
        CRBNode *parent, **slot;

        assert(!c_rbnode_is_linked(&peer->rb));

        slot = c_rbtree_find_slot(&bus->peers,
                                  peer_compare,
                                  &peer->id,
                                  &parent);
        assert(slot); /* peer->id is guaranteed to be unique */
        c_rbtree_add(&bus->peers, parent, slot, &peer->rb);

        driver_notify_name_owner_change(NULL, NULL, peer);
}

void bus_unregister_peer(Bus *bus, Peer *peer) {
        assert(c_rbnode_is_linked(&peer->rb));

        driver_notify_name_owner_change(NULL, peer, NULL);

        c_rbtree_remove_init(&bus->peers, &peer->rb);
}

Peer *bus_find_peer(Bus *bus, uint64_t id) {
        return c_rbtree_find_entry(&bus->peers, peer_compare, &id, Peer, rb);
}
