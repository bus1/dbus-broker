/*
 * Bus Context
 */

#include <c-macro.h>
#include <stdlib.h>
#include <sys/auxv.h>
#include <sys/socket.h>
#include "bus.h"
#include "dbus/address.h"
#include "driver.h"
#include "match.h"
#include "name.h"
#include "util/error.h"
#include "util/user.h"

int bus_init(Bus *bus,
             unsigned int max_bytes,
             unsigned int max_fds,
             unsigned int max_peers,
             unsigned int max_names,
             unsigned int max_matches) {
        unsigned int maxima[] = { max_bytes, max_fds, max_peers, max_names, max_matches };
        void *random;
        int r;

        bus->users = (UserRegistry)USER_REGISTRY_NULL;
        activation_registry_init(&bus->activations);
        match_registry_init(&bus->wildcard_matches);
        match_registry_init(&bus->driver_matches);
        name_registry_init(&bus->names);
        peer_registry_init(&bus->peers);
        bus->metrics = (Metrics)METRICS_INIT;
        bus->user = NULL;
        bus->pid = 0;

        random = (void *)getauxval(AT_RANDOM);
        assert(random);
        memcpy(bus->guid, random, sizeof(bus->guid));

        static_assert(_USER_SLOT_N == C_ARRAY_SIZE(maxima),
                      "User accounting slot mismatch");

        r = user_registry_init(&bus->users, _USER_SLOT_N, maxima);
        if (r)
                return error_fold(r);

        return 0;
}

void bus_deinit(Bus *bus) {
        bus->pid = 0;
        bus->user = user_unref(bus->user);
        metrics_deinit(&bus->metrics);
        peer_registry_deinit(&bus->peers);
        user_registry_deinit(&bus->users);
        name_registry_deinit(&bus->names);
        match_registry_deinit(&bus->driver_matches);
        match_registry_deinit(&bus->wildcard_matches);
        activation_registry_deinit(&bus->activations);
}

Peer *bus_find_peer_by_name(Bus *bus, Name **namep, const char *name_str) {
        NameOwnership *ownership;
        Address addr;
        Peer *peer = NULL;
        Name *name = NULL;

        address_from_string(&addr, name_str);
        switch (addr.type) {
        case ADDRESS_TYPE_ID:
                peer = peer_registry_find_peer(&bus->peers, addr.id);
                break;
        case ADDRESS_TYPE_NAME:
                name = name_registry_find_name(&bus->names, addr.name);
                if (name) {
                        ownership = c_list_first_entry(&name->ownership_list, NameOwnership, name_link);
                        if (ownership)
                                peer = c_container_of(ownership->owner, Peer, owned_names);
                }
                break;
        }

        if (namep)
                *namep = name;
        return peer;
}
