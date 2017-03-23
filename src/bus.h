#pragma once

/*
 * Bus Context
 */

#include <c-list.h>
#include <c-macro.h>
#include <c-rbtree.h>
#include <stdlib.h>

typedef struct Bus Bus;
typedef struct Peer Peer;
typedef struct NameRegistry NameRegistry;
typedef struct UserRegistry UserRegistry;
typedef struct DispatchContext DispatchContext;

struct Bus {
        DispatchContext *dispatcher;
        CList ready_list;
        NameRegistry *names;
        UserRegistry *users;
        CRBTree peers;
        uint64_t ids;
};

int bus_new(Bus **busp,
            unsigned int max_bytes,
            unsigned int max_fds,
            unsigned int max_names);
Bus *bus_free(Bus *bus);

int bus_run(Bus *bus);

void bus_register_peer(Bus *bus, Peer *peer);
void bus_unregister_peer(Bus *bus, Peer *peer);
Peer *bus_find_peer(Bus *bus, uint64_t id);

C_DEFINE_CLEANUP(Bus *, bus_free);
