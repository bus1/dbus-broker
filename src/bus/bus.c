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
        bus->n_seclabel = 0;
        bus->seclabel = c_free(bus->seclabel);
        bus->pid = 0;
        bus->user = user_unref(bus->user);
        metrics_deinit(&bus->metrics);
        peer_registry_deinit(&bus->peers);
        user_registry_deinit(&bus->users);
        name_registry_deinit(&bus->names);
        match_registry_deinit(&bus->sender_matches);
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

static int bus_log_commit_policy(Bus *bus, const char *action, const char *policy_type, uint64_t sender_id, uint64_t receiver_id,
                                 NameSet *sender_names, NameSet *receiver_names, const char *sender_label, const char *receiver_label,
                                 Message *message) {
        Log *log = bus->log;
        int r;

        message_log_append(message, log);

        log_appendf(log, "DBUS_BROKER_TRANSMIT_ACTION=%s\n", action);

        if (policy_type)
                log_appendf(log, "DBUS_BROKER_POLICY_TYPE=%s\n", policy_type);

        if (sender_label)
                log_appendf(log, "DBUS_BROKER_SENDER_SECURITY_LABEL=%s\n",
                            sender_label);

        if (receiver_label)
                log_appendf(log, "DBUS_BROKER_RECEIVER_SECURITY_LABEL=%s\n",
                            receiver_label);

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

        if (sender_names) {
                if (sender_names->type == NAME_SET_TYPE_OWNER) {
                        NameOwnership *ownership;
                        size_t i = 0;

                        c_rbtree_for_each_entry(ownership,
                                                &sender_names->owner->ownership_tree,
                                                owner_node)
                                log_appendf(log,
                                            "DBUS_BROKER_SENDER_WELL_KNOWN_NAME_%zu=%s\n",
                                            i++, ownership->name->name);
                } else if (sender_names->type == NAME_SET_TYPE_SNAPSHOT) {
                        for (size_t i = 0; i < sender_names->snapshot->n_names; ++i)
                                log_appendf(log,
                                            "DBUS_BROKER_SENDER_WELL_KNOWN_NAME_%zu=%s\n",
                                            i, sender_names->snapshot->names[i]->name);
                }
        }

        if (receiver_names) {
                if (receiver_names->type == NAME_SET_TYPE_OWNER) {
                        NameOwnership *ownership;
                        size_t i = 0;

                        c_rbtree_for_each_entry(ownership,
                                                &receiver_names->owner->ownership_tree,
                                                owner_node)
                                log_appendf(log,
                                            "DBUS_BROKER_RECEIVER_WELL_KNOWN_NAME_%zu=%s\n",
                                            i++, ownership->name->name);
                } else if (receiver_names->type == NAME_SET_TYPE_SNAPSHOT) {
                        for (size_t i = 0; i < receiver_names->snapshot->n_names; ++i)
                                log_appendf(log,
                                            "DBUS_BROKER_RECEIVER_WELL_KNOWN_NAME_%zu=%s\n",
                                            i, receiver_names->snapshot->names[i]->name);
                }
        }

        r = log_commitf(log, ":1.%llu failed to %s message, due to policy.", sender_id, action);
        if (r)
                return error_fold(r);

        return 0;
}

int bus_log_commit_policy_send(Bus *bus, int policy_type, uint64_t sender_id, uint64_t receiver_id, NameSet *sender_names, NameSet *receiver_names, const char *sender_label, const char *receiver_label, Message *message) {
        const char *policy_type_str;

        switch (policy_type) {
        case BUS_LOG_POLICY_TYPE_INTERNAL:
                policy_type_str = "internal";
                break;
        case BUS_LOG_POLICY_TYPE_SELINUX:
                policy_type_str = "selinux";
                break;
        default:
                assert(0);
        }

        return bus_log_commit_policy(bus, "send", policy_type_str, sender_id, receiver_id, sender_names, receiver_names, sender_label, receiver_label, message);
}

int bus_log_commit_policy_receive(Bus *bus, uint64_t receiver_id, uint64_t sender_id, NameSet *sender_names, NameSet *receiver_names, Message *message) {
        return bus_log_commit_policy(bus, "receive", "internal", sender_id, receiver_id, sender_names, receiver_names, NULL, NULL, message);
}

int bus_log_commit_metrics(Bus *bus) {
        Metrics *metrics = &bus->metrics;
        Log *log = bus->log;
        double stddev;
        int r;

        stddev = metrics_read_standard_deviation(metrics);
/* XXX: this makes the CI fail
        log_appendf(log,
                    "DBUS_BROKER_METRICS_DISPATCH_COUNT=%"PRIu64"\n"
                    "DBUS_BROKER_METRICS_DISPATCH_MIN=%"PRIu64"\n"
                    "DBUS_BROKER_METRICS_DISPATCH_MAX=%"PRIu64"\n"
                    "DBUS_BROKER_METRICS_DISPATCH_AVG=%"PRIu64"\n"
                    "DBUS_BROKER_METRICS_DISPATCH_STDDEV=%.0f\n",
                    metrics->count,
                    metrics->minimum,
                    metrics->maximum,
                    metrics->average,
                    stddev);
*/
        r = log_commitf(log,
                       "Dispatched %"PRIu64" messages @ %"PRIu64"(±%.0f)μs / message.",
                       metrics->count,
                       metrics->average / 1000,
                       stddev / 1000);
        if (r)
                return error_fold(r);

        return 0;
}
