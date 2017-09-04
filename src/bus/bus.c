/*
 * Bus Context
 */

#include <c-macro.h>
#include <stdlib.h>
#include <sys/auxv.h>
#include <sys/socket.h>
#include "bus/bus.h"
#include "bus/driver.h"
#include "bus/match.h"
#include "bus/name.h"
#include "dbus/address.h"
#include "util/error.h"
#include "util/log.h"
#include "util/user.h"

int bus_init(Bus *bus,
             Log *log,
             unsigned int max_bytes,
             unsigned int max_fds,
             unsigned int max_matches,
             unsigned int max_objects) {
        unsigned int maxima[] = { max_bytes, max_fds, max_matches, max_objects };
        void *random;
        int r;

        *bus = (Bus)BUS_NULL(*bus);
        bus->log = log;

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
                        ownership = name_primary(name);
                        if (ownership)
                                peer = c_container_of(ownership->owner, Peer, owned_names);
                }
                break;
        }

        if (namep)
                *namep = name;
        return peer;
}

static int bus_log_commit_policy(Bus *bus, const char *action, uint64_t sender_id, uint64_t receiver_id, Message *message) {
        Log *log = bus->log;
        int r;

        message_log_append(message, log);

        log_appendf(log, "DBUS_BROKER_TRANSMIT_ACTION=%s\n", action);

        if (sender_id == ADDRESS_ID_INVALID) {
                log_appendf(log,
                            "DBUS_BROKER_SENDER_UNIQUE_NAME=org.freedesktop.DBus\n");
        } else {
                log_appendf(log,
                            "DBUS_BROKER_SENDER_UNIQUE_NAME=:1.%llu\n",
                            sender_id);
        }

        if (receiver_id == ADDRESS_ID_INVALID) {
                log_appendf(log,
                            "DBUS_BOKER_RECEIVER_UNIQUE_NAME=org.freedesktop.DBus\n");
        } else {
                log_appendf(log,
                            "DBUS_BROKER_RECEIVER_UNIQUE_NAME=:1.%llu\n",
                            receiver_id);
        }

        r = log_commitf(log, ":1.%llu failed to %s message, due to policy.", sender_id, action);
        if (r)
                return error_fold(r);

        return 0;
}

int bus_log_commit_policy_send(Bus *bus, uint64_t sender_id, uint64_t receiver_id, Message *message) {
        return bus_log_commit_policy(bus, "send", sender_id, receiver_id, message);
}

int bus_log_commit_policy_receive(Bus *bus, uint64_t receiver_id, uint64_t sender_id, Message *message) {
        return bus_log_commit_policy(bus, "receive", sender_id, receiver_id, message);
}
