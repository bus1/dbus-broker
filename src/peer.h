#pragma once

/*
 * Peers
 */

#include <c-macro.h>
#include <c-rbtree.h>
#include <stdlib.h>
#include <sys/types.h>
#include "dbus/connection.h"
#include "match.h"
#include "name.h"
#include "reply.h"
#include "util/metrics.h"

typedef struct Bus Bus;
typedef struct DispatchContext DispatchContext;
typedef struct Peer Peer;
typedef struct PeerRegistry PeerRegistry;
typedef struct Socket Socket;
typedef struct User User;

enum {
        _PEER_E_SUCCESS,

        PEER_E_QUOTA,
};

struct Peer {
        Bus *bus;
        User *user;
        pid_t pid;
        char *seclabel;
        size_t n_seclabel;

        uint64_t id;
        CRBNode registry_node;

        Connection connection;
        bool registered : 1;
        bool monitor : 1;

        NameOwner owned_names;
        MatchRegistry matches;
        MatchOwner owned_matches;
        ReplyRegistry replies_outgoing;
        ReplyOwner owned_replies;

        Metrics metrics;
};

struct PeerRegistry {
        CRBTree peer_tree;
        uint64_t ids;
};

int peer_new_with_fd(Peer **peerp, Bus *bus, const char guid[], DispatchContext *dispatcher, int fd);
Peer *peer_free(Peer *peer);

int peer_spawn(Peer *peer);

void peer_register(Peer *peer);
void peer_unregister(Peer *peer);

void peer_registry_init(PeerRegistry *registry);
void peer_registry_deinit(PeerRegistry *registry);
void peer_registry_flush(PeerRegistry *registry);
Peer *peer_registry_find_peer(PeerRegistry *registry, uint64_t id);

static inline bool peer_is_registered(Peer *peer) {
        return peer->registered;
}

C_DEFINE_CLEANUP(Peer *, peer_free);
