#pragma once

/*
 * Peers
 */

#include <c-macro.h>
#include <c-rbtree.h>
#include <stdlib.h>
#include <sys/types.h>
#include "reply.h"
#include "sasl.h"
#include "util/dispatch.h"

typedef struct Bus Bus;
typedef struct Peer Peer;
typedef struct Socket Socket;
typedef struct UserEntry UserEntry;

struct Peer {
        Bus *bus;

        SASL sasl;
        bool authenticated : 1;

        DispatchFile dispatch_file;
        Socket *socket;

        UserEntry *user;
        pid_t pid;
        char *seclabel;
        size_t n_seclabel;

        ReplyRegistry replies_outgoing;

        CList replies_incoming;
        CRBTree match_rules;
        CRBTree names;

        CRBNode rb;
        uint64_t id;
};

int peer_new(Peer **peerp,
             Bus *bus,
             int fd);
Peer *peer_free(Peer *peer);

int peer_dispatch(DispatchFile *file, uint32_t mask);

void peer_start(Peer *peer);
void peer_stop(Peer *peer);

static inline bool peer_is_registered(Peer *peer) {
        return c_rbnode_is_linked(&peer->rb);
}

C_DEFINE_CLEANUP(Peer *, peer_free);
