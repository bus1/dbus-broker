/*
 * Bus Context
 */

#include <c-macro.h>
#include <stdlib.h>
#include <sys/types.h>
#include "bus.h"
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

        user_registry_free(bus->users);
        name_registry_free(bus->names);

        free(bus);

        return NULL;
}
