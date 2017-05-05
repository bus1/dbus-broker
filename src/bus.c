/*
 * Bus Context
 */

#include <c-macro.h>
#include <stdlib.h>
#include <sys/socket.h>
#include "bus.h"
#include "dbus/unique-name.h"
#include "driver.h"
#include "match.h"
#include "name.h"
#include "user.h"
#include "util/dispatch.h"
#include "util/error.h"

int bus_new(Bus **busp,
            unsigned int max_bytes,
            unsigned int max_fds,
            unsigned int max_peers,
            unsigned int max_names,
            unsigned int max_matches) {
        _c_cleanup_(bus_freep) Bus *bus = NULL;
        int r;

        bus = calloc(1, sizeof(*bus));
        if (!bus)
                return error_origin(-ENOMEM);

        bus->listener_list = (CList)C_LIST_INIT(bus->listener_list);
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

        *busp = bus;
        bus = NULL;
        return 0;
}

Bus *bus_free(Bus *bus) {
        if (!bus)
                return NULL;

        assert(c_list_is_empty(&bus->listener_list));

        dispatch_context_deinit(&bus->dispatcher);
        peer_registry_deinit(&bus->peers);
        user_registry_deinit(&bus->users);
        name_registry_deinit(&bus->names);
        match_registry_deinit(&bus->driver_matches);
        match_registry_deinit(&bus->wildcard_matches);

        free(bus);

        return NULL;
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
