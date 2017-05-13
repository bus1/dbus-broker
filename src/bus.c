/*
 * Bus Context
 */

#include <c-macro.h>
#include <stdlib.h>
#include <sys/auxv.h>
#include <sys/socket.h>
#include "bus.h"
#include "dbus/unique-name.h"
#include "driver.h"
#include "match.h"
#include "name.h"
#include "user.h"
#include "util/error.h"

void bus_init(Bus *bus,
              unsigned int max_bytes,
              unsigned int max_fds,
              unsigned int max_peers,
              unsigned int max_names,
              unsigned int max_matches) {
        void *random;

        bus->listener_tree = (CRBTree){};

        activation_registry_init(&bus->activations);
        match_registry_init(&bus->wildcard_matches);
        match_registry_init(&bus->driver_matches);
        name_registry_init(&bus->names);
        user_registry_init(&bus->users, max_bytes, max_fds, max_peers, max_names, max_matches);
        peer_registry_init(&bus->peers);

        random = (void *)getauxval(AT_RANDOM);
        assert(random);
        memcpy(bus->guid, random, sizeof(bus->guid));
}

void bus_deinit(Bus *bus) {
        assert(!bus->n_eavesdrop);
        assert(!bus->listener_tree.root);

        peer_registry_deinit(&bus->peers);
        user_registry_deinit(&bus->users);
        name_registry_deinit(&bus->names);
        match_registry_deinit(&bus->driver_matches);
        match_registry_deinit(&bus->wildcard_matches);
        activation_registry_deinit(&bus->activations);
}

/* XXX: use proper return codes */
Peer *bus_find_peer_by_name(Bus *bus, const char *name) {
        int r;

        if (*name != ':') {
                return c_container_of(name_registry_resolve_owner(&bus->names, name), Peer, owned_names);
        } else {
                uint64_t id;

                r = unique_name_to_id(name, &id);
                if (r < 0)
                        return NULL;

                return peer_registry_find_peer(&bus->peers, id);
        }
}
