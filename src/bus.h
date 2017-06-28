#pragma once

/*
 * Bus Context
 */

#include <c-macro.h>
#include <c-rbtree.h>
#include <stdlib.h>
#include "listener.h"
#include "match.h"
#include "name.h"
#include "peer.h"
#include "util/metrics.h"
#include "util/user.h"

enum {
        _BUS_E_SUCCESS,

        BUS_E_FAILURE,
};

typedef struct Bus Bus;
typedef struct Connection Connection;
typedef struct Message Message;
typedef struct User User;

struct Bus {
        Connection *controller;
        User *user;
        pid_t pid;
        char guid[16];

        UserRegistry users;
        NameRegistry names;
        MatchRegistry wildcard_matches;
        MatchRegistry driver_matches;
        PeerRegistry peers;

        uint64_t transaction_ids;
        uint64_t listener_ids;

        Metrics metrics;
};

#define BUS_NULL(_x) {                                                                          \
                .users = (UserRegistry)USER_REGISTRY_NULL,                                      \
                .wildcard_matches = (MatchRegistry)MATCH_REGISTRY_INIT((_x).wildcard_matches),  \
                .driver_matches = (MatchRegistry)MATCH_REGISTRY_INIT((_x).driver_matches),      \
                .names = (NameRegistry)NAME_REGISTRY_INIT,                                      \
                .peers = (PeerRegistry)PEER_REGISTRY_INIT,                                      \
                .metrics = (Metrics)METRICS_INIT,                                               \
        }

int bus_init(Bus *bus,
             unsigned int max_bytes,
             unsigned int max_fds,
             unsigned int max_peers,
             unsigned int max_names,
             unsigned int max_matches);
void bus_deinit(Bus *bus);

Peer *bus_find_peer_by_name(Bus *bus, Name **namep, const char *name);
