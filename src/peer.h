#pragma once

/*
 * Peers
 */

#include <c-macro.h>
#include <c-rbtree.h>
#include <stdlib.h>
#include <sys/types.h>
#include "dbus/connection.h"
#include "dbus/sasl.h"
#include "match.h"
#include "reply.h"
#include "util/dispatch.h"
#include "util/metrics.h"

typedef struct Bus Bus;
typedef struct Peer Peer;
typedef struct PeerRegistry PeerRegistry;
typedef struct Socket Socket;
typedef struct UserEntry UserEntry;

enum {
        _PEER_E_SUCCESS,

        PEER_E_QUOTA,
};

struct Peer {
        Bus *bus;

        Connection connection;
        bool registered : 1;

        UserEntry *user;
        pid_t pid;
        char *seclabel;
        size_t n_seclabel;

        MatchRegistry matches;
        ReplyRegistry replies_outgoing;
        CRBTree names;

        CList replies_incoming;
        CRBTree match_rules;

        Metrics metrics;

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

int peer_start(Peer *peer);
void peer_stop(Peer *peer);

void peer_register(Peer *peer);
void peer_unregister(Peer *peer);

int peer_queue_message(Peer *receiver, Peer *sender, uint32_t serial, Message *message);

void peer_registry_init(PeerRegistry *registry);
void peer_registry_deinit(PeerRegistry *registry);
void peer_registry_flush(PeerRegistry *registry);
Peer *peer_registry_find_peer(PeerRegistry *registry, uint64_t id);

static inline bool peer_is_registered(Peer *peer) {
        return peer->registered;
}

C_DEFINE_CLEANUP(Peer *, peer_free);
