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
        uint64_t id;
};

int peer_new(Peer **peerp, uint64_t id, UserEntry *user);
Peer *peer_free(Peer *peer);

C_DEFINE_CLEANUP(Peer *, peer_free);
