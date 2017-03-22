#pragma once

/*
 * Peers
 */

#include <c-macro.h>
#include <c-rbtree.h>
#include <stdlib.h>

typedef struct Peer Peer;
typedef struct UserEntry UserEntry;
typedef struct NameRegistry NameRegistry;

struct Peer {
        UserEntry *user;
        CRBTree names;
        CRBNode rb;
        char unique_name[3 + C_DECIMAL_MAX(uint64_t)];
};

int peer_new(Peer **peerp, UserEntry *user);
Peer *peer_free(Peer *peer);

C_DEFINE_CLEANUP(Peer *, peer_free);
