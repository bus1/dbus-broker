#pragma once

/*
 * Bus Context
 */

#include <c-list.h>
#include <c-macro.h>
#include <c-rbtree.h>
#include <stdlib.h>
#include "match.h"
#include "name.h"
#include "user.h"
#include "util/dispatch.h"

enum {
        _BUS_E_SUCCESS,

        BUS_E_FAILURE,
};

typedef struct Bus Bus;
typedef struct Peer Peer;

struct Bus {
        char guid[16];
        DispatchContext dispatcher;
        DispatchFile accept_file;
        DispatchFile signal_file;
        int accept_fd;
        int signal_fd;
        CList ready_list;
        NameRegistry names;
        UserRegistry users;
        MatchRegistry matches;
        CRBTree peers;
        uint64_t ids;
};

int bus_new(Bus **busp,
            int accept_fd,
            unsigned int max_bytes,
            unsigned int max_fds,
            unsigned int max_peers,
            unsigned int max_names,
            unsigned int max_matches);
Bus *bus_free(Bus *bus);

int bus_run(Bus *bus);

void bus_register_peer(Bus *bus, Peer *peer);
void bus_unregister_peer(Bus *bus, Peer *peer);
Peer *bus_find_peer(Bus *bus, uint64_t id);
Peer *bus_find_peer_by_name(Bus *bus, const char *name);

C_DEFINE_CLEANUP(Bus *, bus_free);
