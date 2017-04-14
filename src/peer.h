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
typedef struct PeerRegistry PeerRegistry;
typedef struct Socket Socket;
typedef struct UserEntry UserEntry;

struct Peer {
        Bus *bus;

        SASL sasl;
        bool authenticated : 1;
        bool registered : 1;

        DispatchFile dispatch_file;
        Socket *socket;

        UserEntry *user;
        pid_t pid;
        char *seclabel;
        size_t n_seclabel;

        ReplyRegistry replies_outgoing;
        CRBTree names;

        CList replies_incoming;
        CRBTree match_rules;

        CRBNode rb;
        uint64_t id;
};

struct PeerRegistry {
        CRBTree peers;
        uint64_t ids;
};

int peer_new(Peer **peerp, Bus *bus, int fd);
Peer *peer_free(Peer *peer);

int peer_dispatch(DispatchFile *file, uint32_t mask);

void peer_start(Peer *peer);
void peer_stop(Peer *peer);

void peer_register(Peer *peer);
void peer_unregister(Peer *peer);

int peer_id_from_unique_name(const char *name, uint64_t *idp);

void peer_registry_init(PeerRegistry *registry);
void peer_registry_deinit(PeerRegistry *registry);
void peer_registry_flush(PeerRegistry *registry);
Peer *peer_registry_find_peer(PeerRegistry *registry, uint64_t id);

static inline bool peer_is_registered(Peer *peer) {
        return peer->registered;
}

C_DEFINE_CLEANUP(Peer *, peer_free);
