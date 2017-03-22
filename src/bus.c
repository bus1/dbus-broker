/*
 * Bus Context
 */

#include <c-macro.h>
#include <stdlib.h>
#include <sys/types.h>
#include "bus.h"
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

        r = name_registry_new(&bus->names);
        if (r < 0)
                return r;

        r = user_registry_new(&bus->users,
                              max_bytes,
                              max_fds,
                              max_names);
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

        user_registry_free(bus->users);
        name_registry_free(bus->names);

        free(bus);

        return NULL;
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
