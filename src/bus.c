/*
 * Bus Context
 */

#include <c-macro.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include "bus.h"
#include "dispatch.h"
#include "driver.h"
#include "match.h"
#include "name.h"
#include "user.h"

static int bus_accept(DispatchFile *file, uint32_t events) {
        Bus *bus = c_container_of(file, Bus, accept_file);
        _c_cleanup_(c_closep) int fd = -1;
        _c_cleanup_(peer_freep) Peer *peer = NULL;
        int r;

        if (!(events & EPOLLIN))
                return 0;

        fd = accept4(bus->fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (fd < 0) {
                if (errno == EAGAIN) {
                        dispatch_file_clear(file, EPOLLIN);
                        return 0;
                } else if (errno == ECONNRESET || errno == EPERM) {
                        /* ignore pending errors on the new socket */
                        return 0;
                }
                return -errno;
        }

        r = peer_new(&peer, bus, fd);
        if (r < 0)
                return r;
        fd = -1;

        peer_start(peer);

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
        match_registry_init(&bus->matches);
        /* XXX: initialize guid with random data */
        name_registry_init(&bus->names);
        user_registry_init(&bus->users,
                           max_bytes,
                           max_fds,
                           max_peers,
                           max_names,
                           max_matches);
        bus->dispatcher = (DispatchContext)DISPATCH_CONTEXT_NULL;
        bus->accept_file = (DispatchFile)DISPATCH_FILE_NULL(bus->accept_file);

        r = dispatch_context_init(&bus->dispatcher);
        if (r < 0)
                return r;

        r = dispatch_file_init(&bus->accept_file,
                               &bus->dispatcher,
                               &bus->ready_list,
                               bus_accept,
                               fd,
                               EPOLLIN);
        if (r < 0)
                return r;

        dispatch_file_select(&bus->accept_file, EPOLLIN);

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
        dispatch_context_deinit(&bus->dispatcher);
        user_registry_deinit(&bus->users);
        name_registry_deinit(&bus->names);
        match_registry_deinit(&bus->matches);

        free(bus);

        return NULL;
}

int bus_dispatch(Bus *bus) {
        DispatchFile *file;
        CList list = C_LIST_INIT(list);
        int r;

        while ((file = c_list_first_entry(&bus->ready_list, DispatchFile, ready_link))) {
                c_list_unlink(&file->ready_link);
                c_list_link_tail(&list, &file->ready_link);

                r = file->fn(file, file->user_mask & file->events);
                if (r < 0)
                        return r;
        }

        c_list_swap(&bus->ready_list, &list);

        return 0;
}

int bus_run(Bus *bus) {
        int r;

        for (;;) {
                r = dispatch_context_poll(&bus->dispatcher, c_list_is_empty(&bus->ready_list) ? -1 : 0);
                if (r < 0)
                        return r;

                r = bus_dispatch(bus);
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
