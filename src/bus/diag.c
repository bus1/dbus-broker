/*
 * Bus Diagnostics
 */

#include <c-stdaux.h>
#include <stdlib.h>
#include "bus/bus.h"
#include "bus/name.h"
#include "bus/peer.h"
#include "catalog/catalog-ids.h"
#include "dbus/message.h"
#include "util/error.h"
#include "util/log.h"
#include "util/sampler.h"

static void diag_append_message(Log *log, Message *message) {
        log_appendf(
                log,
                "DBUS_BROKER_MESSAGE_DESTINATION=%s\n"
                "DBUS_BROKER_MESSAGE_SERIAL=%"PRIu32"\n"
                "DBUS_BROKER_MESSAGE_SIGNATURE=%s\n"
                "DBUS_BROKER_MESSAGE_UNIX_FDS=%"PRIu32"\n",
                message->metadata.fields.destination ?: "<broadcast>",
                message->metadata.header.serial,
                message->metadata.fields.signature ?: "<missing>",
                message->metadata.fields.unix_fds
        );

        switch (message->metadata.header.type) {
        case DBUS_MESSAGE_TYPE_METHOD_CALL:
                log_appendf(
                        log,
                        "DBUS_BROKER_MESSAGE_TYPE=method_call\n"
                        "DBUS_BROKER_MESSAGE_PATH=%s\n"
                        "DBUS_BROKER_MESSAGE_INTERFACE=%s\n"
                        "DBUS_BROKER_MESSAGE_MEMBER=%s\n",
                        message->metadata.fields.path ?: "<missing>",
                        message->metadata.fields.interface ?: "<missing>",
                        message->metadata.fields.member ?: "<missing>"
                );
                break;
        case DBUS_MESSAGE_TYPE_SIGNAL:
                log_appendf(
                        log,
                        "DBUS_BROKER_MESSAGE_TYPE=signal\n"
                        "DBUS_BROKER_MESSAGE_PATH=%s\n"
                        "DBUS_BROKER_MESSAGE_INTERFACE=%s\n"
                        "DBUS_BROKER_MESSAGE_MEMBER=%s\n",
                        message->metadata.fields.path ?: "<missing>",
                        message->metadata.fields.interface ?: "<missing>",
                        message->metadata.fields.member ?: "<missing>"
                );
                break;
        case DBUS_MESSAGE_TYPE_METHOD_RETURN:
                log_appendf(
                        log,
                        "DBUS_BROKER_MESSAGE_TYPE=method_return\n"
                        "MESSAGE_REPLY_SERIAL=%"PRIu32"\n",
                        message->metadata.fields.reply_serial
                );
                break;
        case DBUS_MESSAGE_TYPE_ERROR:
                log_appendf(
                        log,
                        "DBUS_BROKER_MESSAGE_TYPE=method_return\n"
                        "DBUS_BROKER_MESSAGE_ERROR_NAME=%s\n"
                        "DBUS_BROKER_MESSAGE_REPLY_SERIAL=%"PRIu32"\n",
                        message->metadata.fields.error_name,
                        message->metadata.fields.reply_serial
                );
                break;
        default:
                log_appendf(
                        log,
                        "DBUS_BROKER_MESSAGE_TYPE=%u\n",
                        message->metadata.header.type
                );
                break;
        }
}

static void diag_append_sndrcv(
        Log *log,
        const char *sndrcv,
        uint64_t sender_id,
        NameSet *sender_names,
        const char *sender_label
) {
        if (sender_label) {
                log_appendf(
                        log,
                        "DBUS_BROKER_%s_SECURITY_LABEL=%s\n",
                        sndrcv,
                        sender_label
                );
        }

        if (sender_id == ADDRESS_ID_INVALID) {
                log_appendf(
                        log,
                        "DBUS_BROKER_%s_UNIQUE_NAME=%s\n",
                        sndrcv,
                        "org.freedesktop.DBus"
                );
        } else {
                log_appendf(
                        log,
                        "DBUS_BROKER_%s_UNIQUE_NAME=:1.%llu\n",
                        sndrcv,
                        sender_id
                );
        }

        if (sender_names) {
                if (sender_names->type == NAME_SET_TYPE_OWNER) {
                        NameOwnership *ownership;
                        size_t i = 0;

                        c_rbtree_for_each_entry(
                                ownership,
                                &sender_names->owner->ownership_tree,
                                owner_node
                        ) {
                                log_appendf(
                                        log,
                                        "DBUS_BROKER_%s_WELL_KNOWN_NAME_%zu=%s\n",
                                        sndrcv,
                                        i++,
                                        ownership->name->name
                                );
                        }
                } else if (sender_names->type == NAME_SET_TYPE_SNAPSHOT) {
                        for (size_t i = 0; i < sender_names->snapshot->n_names; ++i) {
                                log_appendf(
                                        log,
                                        "DBUS_BROKER_%s_WELL_KNOWN_NAME_%zu=%s\n",
                                        sndrcv,
                                        i,
                                        sender_names->snapshot->names[i]->name
                                );
                        }
                }
        }
}

static void diag_append_sender_raw(
        Log *log,
        uint64_t sender_id,
        NameSet *sender_names,
        const char *sender_label
) {
        return diag_append_sndrcv(
                log,
                "SENDER",
                sender_id,
                sender_names,
                sender_label
        );
}

static void diag_append_sender(Peer *peer) {
        NameSet peer_names = NAME_SET_INIT_FROM_OWNER(&peer->owned_names);
        return diag_append_sender_raw(
                peer->bus->log,
                peer->id,
                &peer_names,
                peer->policy->seclabel
        );
}

static void diag_append_receiver_raw(
        Log *log,
        uint64_t receiver_id,
        NameSet *receiver_names,
        const char *receiver_label
) {
        return diag_append_sndrcv(
                log,
                "RECEIVER",
                receiver_id,
                receiver_names,
                receiver_label
        );
}

static void diag_append_receiver(Peer *peer) {
        NameSet peer_names = NAME_SET_INIT_FROM_OWNER(&peer->owned_names);
        return diag_append_receiver_raw(
                peer->bus->log,
                peer->id,
                &peer_names,
                peer->policy->seclabel
        );
}

static void diag_append_transaction(
        Peer *sender,
        Peer *receiver,
        Message *m
) {
        diag_append_sender(sender);
        diag_append_receiver(receiver);
        diag_append_message(receiver->bus->log, m);
}

int diag_quota_queue_reply(
        Peer *sender,
        Peer *receiver,
        Message *m,
        LogProvenance prov
) {
        log_append_common(
                receiver->bus->log,
                LOG_WARNING,
                0,
                DBUS_BROKER_CATALOG_QUOTA_QUEUE_REPLY,
                prov
        );
        diag_append_transaction(sender, receiver, m);
        return log_commitf(
                receiver->bus->log,
                "Peer :1.%llu is being disconnected as it does not have the resources to receive a reply it requested.",
                receiver->id
        );
}

int diag_quota_dequeue(Peer *peer, LogProvenance prov) {
        log_append_common(
                peer->bus->log,
                LOG_WARNING,
                0,
                DBUS_BROKER_CATALOG_QUOTA_DEQUEUE,
                prov
        );
        diag_append_sender(peer);
        return log_commitf(
                peer->bus->log,
                "Peer :1.%llu is being disconnected as it does not have the resources to queue further messages.",
                peer->id
        );
}

int diag_dispatch_stats(Bus *bus, LogProvenance prov) {
        Sampler *sampler = &bus->sampler;
        double stddev;

        stddev = sampler_read_standard_deviation(sampler);
        log_appendf(bus->log,
                    "DBUS_BROKER_METRICS_DISPATCH_COUNT=%"PRIu64"\n"
                    "DBUS_BROKER_METRICS_DISPATCH_MIN=%"PRIu64"\n"
                    "DBUS_BROKER_METRICS_DISPATCH_MAX=%"PRIu64"\n"
                    "DBUS_BROKER_METRICS_DISPATCH_AVG=%"PRIu64"\n"
                    "DBUS_BROKER_METRICS_DISPATCH_STDDEV=%.0f\n",
                    sampler->count,
                    sampler->minimum,
                    sampler->maximum,
                    sampler->average,
                    stddev);
        log_append_common(
                bus->log,
                LOG_INFO,
                0,
                DBUS_BROKER_CATALOG_DISPATCH_STATS,
                prov
        );
        return log_commitf(
                bus->log,
                "Dispatched %"PRIu64" messages @ %"PRIu64"(±%.0f)μs / message.",
                sampler->count,
                sampler->average / 1000,
                stddev / 1000
        );
}
