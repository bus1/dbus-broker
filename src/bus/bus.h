#pragma once

/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: D-Bus Broker Developers */

/*
 * Bus Context
 */

#include <c-rbtree.h>
#include <c-stdaux.h>
#include <stdlib.h>
#include <sys/types.h>
#include "bus/listener.h"
#include "bus/match.h"
#include "bus/name.h"
#include "bus/peer.h"
#include "dbus/protocol.h"
#include "util/sampler.h"
#include "util/user.h"

enum {
        _BUS_E_SUCCESS,

        BUS_E_FAILURE,
};

/*
 * Reasons a peer can be disconnected for running out of its resource quota.
 * These are the terminal events of a peer that stopped draining its socket,
 * so they are tracked separately to tell the different queues apart.
 */
enum {
        BUS_QUOTA_DISCONNECT_DEQUEUE,
        BUS_QUOTA_DISCONNECT_REPLY,
        BUS_QUOTA_DISCONNECT_BROADCAST,
        _BUS_QUOTA_DISCONNECT_N,
};

static inline const char *bus_quota_disconnect_to_string(size_t reason) {
        switch (reason) {
        case BUS_QUOTA_DISCONNECT_DEQUEUE:
                return "dequeue";
        case BUS_QUOTA_DISCONNECT_REPLY:
                return "reply";
        case BUS_QUOTA_DISCONNECT_BROADCAST:
                return "broadcast";
        default:
                c_assert(0);
                abort();
        }
}

enum {
        BUS_LOG_POLICY_TYPE_INTERNAL,
        BUS_LOG_POLICY_TYPE_SELINUX,
        BUS_LOG_POLICY_TYPE_APPARMOR,
};

typedef struct Bus Bus;
typedef struct BusMetrics BusMetrics;
typedef struct Log Log;
typedef struct Message Message;
typedef struct User User;

/*
 * Cumulative event counters. Unlike the gauges scattered across the different
 * registries, these are monotonic and never reset, so they can be scraped as
 * rates. The broker is single-threaded, hence plain increments suffice.
 */
struct BusMetrics {
        uint64_t n_dispatched[_DBUS_MESSAGE_TYPE_N];
        uint64_t n_dispatched_bytes;
        uint64_t n_broadcast_deliveries;
        uint64_t n_quota_disconnects[_BUS_QUOTA_DISCONNECT_N];
        uint64_t n_connections_refused;
};

struct Bus {
        Log *log;
        User *user;
        pid_t pid;
        int pid_fd;
        gid_t *gids;
        size_t n_gids;
        char *seclabel;
        size_t n_seclabel;
        char machine_id[33];
        char guid[16];

        UserRegistry users;
        NameRegistry names;
        MatchCounters match_counters;
        MatchRegistry wildcard_matches;
        MatchRegistry sender_matches;
        PeerRegistry peers;

        uint64_t n_monitors;
        uint64_t listener_ids;
        uint64_t activation_ids;
        uint64_t stats_ids;

        BusMetrics metrics;
        Sampler sampler;
};

#define BUS_NULL(_x) {                                                          \
                .pid_fd = -1,                                                   \
                .users = USER_REGISTRY_NULL,                                    \
                .names = NAME_REGISTRY_INIT,                                    \
                .match_counters = MATCH_COUNTERS_INIT,                          \
                .wildcard_matches = MATCH_REGISTRY_INIT((_x).wildcard_matches), \
                .sender_matches = MATCH_REGISTRY_INIT((_x).sender_matches),     \
                .peers = PEER_REGISTRY_INIT,                                    \
                .sampler = SAMPLER_INIT(CLOCK_THREAD_CPUTIME_ID),               \
        }

int bus_init(Bus *bus,
             Log *log,
             const char *machine_id,
             unsigned int max_bytes,
             unsigned int max_fds,
             unsigned int max_matches,
             unsigned int max_objects);
void bus_deinit(Bus *bus);

Peer *bus_find_peer_by_name(Bus *bus, Name **namep, const char *name);
void bus_get_monitor_destinations(Bus *bus, CList *destinations, Peer *sender, MessageMetadata *metadata);
void bus_get_broadcast_destinations(Bus *bus, CList *destinations, MatchRegistry *matches, Peer *sender, MessageMetadata *metadata);

void bus_log_append_receiver(Bus *bus, uint64_t receiver_id, NameSet *receiver_names, const char *receiver_label);
void bus_log_append_sender(Bus *bus, uint64_t sender_id, NameSet *sender_names, const char *sender_label);
void bus_log_append_transaction(Bus *bus, uint64_t sender_id, uint64_t receiver_id, NameSet *sender_names, NameSet *receiver_names, const char *sender_label, const char *receiver_label, Message *message);
void bus_log_append_policy_send(Bus *bus, int policy_type, uint64_t sender_id, uint64_t receiver_id, NameSet *sender_names, NameSet *receiver_names, const char *sender_label, const char *receiver_label, Message *message);
void bus_log_append_policy_receive(Bus *bus, int policy_type, uint64_t sender_id, uint64_t receiver_id, NameSet *sender_names, NameSet *receievr_names, Message *message);
