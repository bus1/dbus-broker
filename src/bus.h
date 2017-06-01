#pragma once

/*
 * Bus Context
 */

#include <c-macro.h>
#include <c-rbtree.h>
#include <stdlib.h>
#include "activation.h"
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
typedef struct Message Message;
typedef struct User User;

struct Bus {
        Connection *controller;
        User *user;
        pid_t pid;
        char guid[16];

        CRBTree listener_tree;
        UserRegistry users;
        ActivationRegistry activations;
        NameRegistry names;
        MatchRegistry wildcard_matches;
        MatchRegistry driver_matches;
        PeerRegistry peers;

        uint64_t transaction_ids;
        uint64_t listener_ids;
};

int bus_init(Bus *bus,
             unsigned int max_bytes,
             unsigned int max_fds,
             unsigned int max_peers,
             unsigned int max_names,
             unsigned int max_matches);
void bus_deinit(Bus *bus);

Peer *bus_find_peer_by_name(Bus *bus, const char *name);
int bus_broadcast(Bus *bus, Peer *sender, MatchFilter *filter, Message *message);
