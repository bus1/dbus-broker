/*
 * Bus Context
 */

#include <c-rbtree.h>
#include <c-stdaux.h>
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
#include "util/sampler.h"
#include "util/user.h"

int bus_init(Bus *bus,
             Log *log,
             const char *machine_id,
             unsigned int max_bytes,
             unsigned int max_fds,
             unsigned int max_matches,
             unsigned int max_objects) {
        unsigned int maxima[] = { max_bytes, max_fds, max_matches, max_objects };
        void *random;
        int r;

        static_assert(_USER_SLOT_N == C_ARRAY_SIZE(maxima),
                      "User accounting slot mismatch");

        if (strlen(machine_id) + 1 != sizeof(bus->machine_id))
                return error_origin(-EINVAL);

        *bus = (Bus)BUS_NULL(*bus);
        bus->log = log;

        c_memcpy(bus->machine_id, machine_id, sizeof(bus->machine_id));

        random = (void *)getauxval(AT_RANDOM);
        c_assert(random);
        c_memcpy(bus->guid, random, sizeof(bus->guid));

        r = user_registry_init(&bus->users, log, _USER_SLOT_N, maxima);
        if (r)
                return error_fold(r);

        return 0;
}

void bus_deinit(Bus *bus) {
        bus->n_seclabel = 0;
        bus->seclabel = c_free(bus->seclabel);
        bus->n_gids = 0;
        bus->gids = c_free(bus->gids);
        bus->pid = 0;
        bus->pid_fd = c_close(bus->pid_fd);
        bus->user = user_unref(bus->user);
        sampler_deinit(&bus->sampler);
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

void bus_get_monitor_destinations(Bus *bus, CList *destinations, Peer *sender, MessageMetadata *metadata) {
        if (!bus->n_monitors)
                return;

        match_registry_get_monitors(&bus->wildcard_matches, destinations, metadata);

        if (sender) {
                NameOwnership *ownership;

                c_rbtree_for_each_entry(ownership, &sender->owned_names.ownership_tree, owner_node) {
                        if (!name_ownership_is_primary(ownership))
                                continue;

                        match_registry_get_monitors(&ownership->name->sender_matches, destinations, metadata);
                }

                match_registry_get_monitors(&sender->sender_matches, destinations, metadata);
        } else {
                /* sent from the driver */
                match_registry_get_monitors(&bus->sender_matches, destinations, metadata);
        }
}

void bus_get_broadcast_destinations(Bus *bus, CList *destinations, MatchRegistry *matches, Peer *sender, MessageMetadata *metadata) {
        match_registry_get_subscribers(&bus->wildcard_matches, destinations, metadata);

        if (matches) {
                match_registry_get_subscribers(matches, destinations, metadata);
        }

        if (sender) {
                NameOwner *owner = &sender->owned_names;
                NameOwnership *ownership;

                c_rbtree_for_each_entry(ownership, &owner->ownership_tree, owner_node) {
                        if (!name_ownership_is_primary(ownership))
                                continue;

                        match_registry_get_subscribers(&ownership->name->sender_matches, destinations, metadata);
                }
        } else {
                /* sent from the driver */
                match_registry_get_subscribers(&bus->sender_matches, destinations, metadata);
        }
}

void bus_log_append_sender(Bus *bus, uint64_t sender_id, NameSet *sender_names, const char *sender_label) {
        Log *log = bus->log;

        if (sender_label)
                log_appendf(log, "DBUS_BROKER_SENDER_SECURITY_LABEL=%s\n",
                            sender_label);

        if (sender_id == ADDRESS_ID_INVALID) {
                log_appendf(log,
                            "DBUS_BROKER_SENDER_UNIQUE_NAME=org.freedesktop.DBus\n");
        } else {
                log_appendf(log,
                            "DBUS_BROKER_SENDER_UNIQUE_NAME=:1.%llu\n",
                            sender_id);
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
}

void bus_log_append_receiver(Bus *bus, uint64_t receiver_id, NameSet *receiver_names, const char *receiver_label) {
        Log *log = bus->log;

        if (receiver_label)
                log_appendf(log, "DBUS_BROKER_RECEIVER_SECURITY_LABEL=%s\n",
                            receiver_label);

        if (receiver_id == ADDRESS_ID_INVALID) {
                log_appendf(log,
                            "DBUS_BOKER_RECEIVER_UNIQUE_NAME=org.freedesktop.DBus\n");
        } else {
                log_appendf(log,
                            "DBUS_BROKER_RECEIVER_UNIQUE_NAME=:1.%llu\n",
                            receiver_id);
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
}

void bus_log_append_transaction(Bus *bus, uint64_t sender_id, uint64_t receiver_id,
                                NameSet *sender_names, NameSet *receiver_names, const char *sender_label, const char *receiver_label,
                                Message *message) {
        message_log_append(message, bus->log);
        bus_log_append_sender(bus, sender_id, sender_names, sender_label);
        bus_log_append_receiver(bus, receiver_id, receiver_names, receiver_label);
}

void bus_log_append_policy_send(Bus *bus, int policy_type, uint64_t sender_id, uint64_t receiver_id, NameSet *sender_names, NameSet *receiver_names, const char *sender_label, const char *receiver_label, Message *message) {
        switch (policy_type) {
        case BUS_LOG_POLICY_TYPE_INTERNAL:
                log_appendf(bus->log, "DBUS_BROKER_POLICY_TYPE=internal\n");
                break;
        case BUS_LOG_POLICY_TYPE_SELINUX:
                log_appendf(bus->log, "DBUS_BROKER_POLICY_TYPE=selinux\n");
                break;
        case BUS_LOG_POLICY_TYPE_APPARMOR:
                log_appendf(bus->log, "DBUS_BROKER_POLICY_TYPE=apparmor\n");
                break;
        default:
                c_assert(0);
                abort();
        }

        log_appendf(bus->log, "DBUS_BROKER_TRANSMIT_ACTION=send\n");
        bus_log_append_transaction(bus, sender_id, receiver_id, sender_names, receiver_names, sender_label, receiver_label, message);
}

void bus_log_append_policy_receive(Bus *bus, int policy_type, uint64_t receiver_id, uint64_t sender_id, NameSet *sender_names, NameSet *receiver_names, Message *message) {
        switch (policy_type) {
        case BUS_LOG_POLICY_TYPE_INTERNAL:
                log_appendf(bus->log, "DBUS_BROKER_POLICY_TYPE=internal\n");
                break;
        case BUS_LOG_POLICY_TYPE_SELINUX:
                log_appendf(bus->log, "DBUS_BROKER_POLICY_TYPE=selinux\n");
                break;
        case BUS_LOG_POLICY_TYPE_APPARMOR:
                log_appendf(bus->log, "DBUS_BROKER_POLICY_TYPE=apparmor\n");
                break;
        default:
                c_assert(0);
                abort();
        }
        log_appendf(bus->log, "DBUS_BROKER_TRANSMIT_ACTION=receive\n");
        bus_log_append_transaction(bus, sender_id, receiver_id, sender_names, receiver_names, NULL, NULL, message);
}
