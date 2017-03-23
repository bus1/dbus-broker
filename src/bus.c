/*
 * Bus Context
 */

#include <c-macro.h>
#include <stdlib.h>
#include "bus.h"
#include "dispatch.h"
#include "driver.h"
#include "name.h"
#include "user.h"

int bus_new(Bus **busp,
            unsigned int max_bytes,
            unsigned int max_fds,
            unsigned int max_names) {
        _c_cleanup_(bus_freep) Bus *bus = NULL;
        int r;

        bus = calloc(1, sizeof(*bus));
        if (!bus)
                return -ENOMEM;

        bus->ready_list = (CList)C_LIST_INIT(bus->ready_list);

        r = name_registry_new(&bus->names);
        if (r < 0)
                return r;

        r = user_registry_new(&bus->users,
                              max_bytes,
                              max_fds,
                              max_names);
        if (r < 0)
                return r;

        r = dispatch_context_new(&bus->dispatcher);
        if (r < 0)
                return r;

        *busp = bus;
        bus = NULL;
        return 0;
}

Bus *bus_free(Bus *bus) {
        if (!bus)
                return NULL;

        assert(!bus->peers.root);
        assert(c_list_is_empty(&bus->ready_list));

        dispatch_context_free(bus->dispatcher);
        user_registry_free(bus->users);
        name_registry_free(bus->names);

        free(bus);

        return NULL;
}

int bus_dispatch(Bus *bus) {
        DispatchFile *file, *safe;
        int r;

        /*
         * XXX: This avoids starvation by dispatching only one event from each
         *      file, but we probably want something better than that.
         */
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

        dbus_driver_notify_name_owner_change(NULL, NULL, peer);
}

void bus_unregister_peer(Bus *bus, Peer *peer) {
        assert(c_rbnode_is_linked(&peer->rb));

        dbus_driver_notify_name_owner_change(NULL, peer, NULL);

        c_rbtree_remove_init(&bus->peers, &peer->rb);
}

Peer *bus_find_peer(Bus *bus, uint64_t id) {
        return c_rbtree_find_entry(&bus->peers, peer_compare, &id, Peer, rb);
}
