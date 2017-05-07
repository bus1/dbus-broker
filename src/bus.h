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
#include "user.h"

enum {
        _BUS_E_SUCCESS,

        BUS_E_FAILURE,
};

typedef struct Bus Bus;
typedef struct Connection Connection;

struct Bus {
        Connection *controller;
        char guid[16];
        CRBTree listener_tree;
        CRBTree activation_tree;
        NameRegistry names;
        UserRegistry users;
        MatchRegistry wildcard_matches;
        MatchRegistry driver_matches;
        PeerRegistry peers;
};

int bus_new(Bus **busp,
            unsigned int max_bytes,
            unsigned int max_fds,
            unsigned int max_peers,
            unsigned int max_names,
            unsigned int max_matches);
Bus *bus_free(Bus *bus);

Peer *bus_find_peer_by_name(Bus *bus, const char *name);

C_DEFINE_CLEANUP(Bus *, bus_free);
