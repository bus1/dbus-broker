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
             const char *machine_id,
             unsigned int max_bytes,
             unsigned int max_fds,
             unsigned int max_matches,
             unsigned int max_objects) {
        unsigned int maxima[] = { max_bytes, max_fds, max_matches, max_objects };
        void *random;
        int r;

        if (strlen(machine_id) + 1 != sizeof(bus->machine_id))
                return error_origin(-EINVAL);

        *bus = (Bus)BUS_NULL(*bus);
        bus->log = log;

        memcpy(bus->machine_id, machine_id, sizeof(bus->machine_id));

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

static int bus_get_monitor_destinations_for_matches(CList *destinations, MatchRegistry *matches, MessageMetadata *metadata) {
        MatchRule *rule;

        for (rule = match_rule_next_monitor_match(matches, NULL, metadata); rule; rule = match_rule_next_monitor_match(matches, rule, metadata)) {
                Peer *receiver = c_container_of(rule->owner, Peer, owned_matches);

                if (c_list_is_linked(&receiver->destinations_link))
                        /* only link a destination once, despite matching in several different ways */
                        continue;

                c_list_link_tail(destinations, &receiver->destinations_link);
        }

        return 0;
}

int bus_get_monitor_destinations(Bus *bus, CList *destinations, Peer *sender, MessageMetadata *metadata) {
        int r;

        if (!bus->n_monitors)
                return 0;

        r = bus_get_monitor_destinations_for_matches(destinations, &bus->wildcard_matches, metadata);
        if (r)
                return error_trace(r);

        if (sender) {
                NameOwnership *ownership;

                c_rbtree_for_each_entry(ownership, &sender->owned_names.ownership_tree, owner_node) {
                        if (!name_ownership_is_primary(ownership))
                                continue;

                        r = bus_get_monitor_destinations_for_matches(destinations, &ownership->name->sender_matches, metadata);
                        if (r)
                                return error_trace(r);
                }

                r = bus_get_monitor_destinations_for_matches(destinations, &sender->sender_matches, metadata);
                if (r)
                        return error_trace(r);
        } else {
                /* sent from the driver */
                r = bus_get_monitor_destinations_for_matches(destinations, &bus->sender_matches, metadata);
                if (r)
                        return error_trace(r);
        }

        return 0;
}

static int bus_get_broadcast_destinations_for_matches(CList *destinations, Peer *sender, MatchRegistry *matches, MessageMetadata *metadata) {
        NameSet sender_names = NAME_SET_INIT_FROM_OWNER(sender ? &sender->owned_names : NULL);
        MatchRule *rule;
        int r;

        for (rule = match_rule_next_subscription_match(matches, NULL, metadata); rule; rule = match_rule_next_subscription_match(matches, rule, metadata)) {
                Peer *receiver = c_container_of(rule->owner, Peer, owned_matches);
                NameSet receiver_names = NAME_SET_INIT_FROM_OWNER(&receiver->owned_names);

                if (c_list_is_linked(&receiver->destinations_link))
                        /* only link a destination once, despite matching in several different ways */
                        continue;

                if (sender) {
                        r = policy_snapshot_check_send(sender->policy,
                                                       receiver->seclabel,
                                                       &receiver_names,
                                                       metadata->fields.interface,
                                                       metadata->fields.member,
                                                       metadata->fields.path,
                                                       metadata->header.type);
                        if (r) {
                                if (r == POLICY_E_ACCESS_DENIED || r == POLICY_E_SELINUX_ACCESS_DENIED)
                                        continue;

                                return error_fold(r);
                        }
                }

                r = policy_snapshot_check_receive(receiver->policy,
                                                  &sender_names,
                                                  metadata->fields.interface,
                                                  metadata->fields.member,
                                                  metadata->fields.path,
                                                  metadata->header.type);
                if (r) {
                        if (r == POLICY_E_ACCESS_DENIED)
                                continue;

                        return error_fold(r);
                }

                c_list_link_tail(destinations, &receiver->destinations_link);
        }

        return 0;
}

int bus_get_broadcast_destinations(Bus *bus, CList *destinations, MatchRegistry *matches, Peer *sender, MessageMetadata *metadata) {
        int r;

        r = bus_get_broadcast_destinations_for_matches(destinations, sender, &bus->wildcard_matches, metadata);
        if (r)
                return error_trace(r);

        if (matches) {
                r = bus_get_broadcast_destinations_for_matches(destinations, sender, matches, metadata);
                if (r)
                        return error_trace(r);
        }

        if (sender) {
                NameOwner *owner = &sender->owned_names;
                NameOwnership *ownership;

                c_rbtree_for_each_entry(ownership, &owner->ownership_tree, owner_node) {
                        if (!name_ownership_is_primary(ownership))
                                continue;

                        r = bus_get_broadcast_destinations_for_matches(destinations, sender, &ownership->name->sender_matches, metadata);
                        if (r)
                                return error_trace(r);
                }
        } else {
                /* sent from the driver */
                r = bus_get_broadcast_destinations_for_matches(destinations, NULL, &bus->sender_matches, metadata);
                if (r)
                        return error_trace(r);
        }

        return 0;
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
