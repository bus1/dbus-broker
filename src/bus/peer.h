#pragma once

/*
 * Peers
 */

#include <c-rbtree.h>
#include <c-stdaux.h>
#include <stdlib.h>
#include <sys/types.h>
#include "bus/match.h"
#include "bus/name.h"
#include "bus/policy.h"
#include "bus/reply.h"
#include "dbus/connection.h"

typedef struct Bus Bus;
typedef struct DispatchContext DispatchContext;
typedef struct Peer Peer;
typedef struct PeerRegistry PeerRegistry;
typedef struct Socket Socket;
typedef struct User User;

enum {
        _PEER_E_SUCCESS,

        PEER_E_QUOTA,

        PEER_E_CONNECTION_REFUSED,

        PEER_E_EOF,
        PEER_E_PROTOCOL_VIOLATION,

        PEER_E_SEND_DENIED,
        PEER_E_RECEIVE_DENIED,

        PEER_E_NAME_RESERVED,
        PEER_E_NAME_UNIQUE,
        PEER_E_NAME_REFUSED,
        PEER_E_NAME_ALREADY_OWNER,
        PEER_E_NAME_IN_QUEUE,
        PEER_E_NAME_EXISTS,
        PEER_E_NAME_NOT_FOUND,
        PEER_E_NAME_NOT_OWNER,

        PEER_E_MATCH_INVALID,
        PEER_E_MATCH_NOT_FOUND,

        PEER_E_EXPECTED_REPLY_EXISTS,
        PEER_E_UNEXPECTED_REPLY,

        PEER_E_UNEXPECTED_FDS,
};

struct Peer {
        Bus *bus;
        User *user;
        pid_t pid;
        int pid_fd;
        gid_t *gids;
        size_t n_gids;
        char *seclabel;
        size_t n_seclabel;
        UserCharge charges[3];

        uint64_t id;
        CRBNode registry_node;
        CList listener_link;

        Connection connection;
        bool registered : 1;
        bool monitor : 1;

        PolicySnapshot *policy;
        NameOwner owned_names;
        MatchRegistry sender_matches;
        MatchRegistry name_owner_changed_matches;
        MatchOwner owned_matches;
        ReplyRegistry replies;
        ReplyOwner owned_replies;
};

#define PEER_INIT(_x) {                                                                                 \
                .charges = { USER_CHARGE_INIT, USER_CHARGE_INIT, USER_CHARGE_INIT },                    \
                .registry_node = C_RBNODE_INIT((_x).registry_node),                                     \
                .listener_link = C_LIST_INIT((_x).listener_link),                                       \
                .connection = CONNECTION_NULL((_x).connection),                                         \
                .owned_names = NAME_OWNER_INIT,                                                         \
                .sender_matches = MATCH_REGISTRY_INIT((_x).sender_matches),                             \
                .name_owner_changed_matches = MATCH_REGISTRY_INIT((_x).name_owner_changed_matches),     \
                .owned_matches = MATCH_OWNER_INIT((_x).owned_matches),                                  \
                .replies = REPLY_REGISTRY_INIT,                                                         \
                .owned_replies = REPLY_OWNER_INIT((_x).owned_replies),                                  \
        }

struct PeerRegistry {
        CRBTree peer_tree;
        uint64_t ids;
        size_t n_peers;
        size_t n_registered;
};

#define PEER_REGISTRY_INIT {}

int peer_new_with_fd(Peer **peerp, Bus *bus, PolicyRegistry *policy, const char guid[], DispatchContext *dispatcher, int fd);
Peer *peer_free(Peer *peer);

int peer_dispatch(DispatchFile *file);
int peer_spawn(Peer *peer);

void peer_register(Peer *peer);
void peer_unregister(Peer *peer);

bool peer_is_privileged(Peer *peer);

int peer_request_name(Peer *peer, const char *name, uint32_t flags, NameChange *change);
int peer_release_name(Peer *peer, const char *name, NameChange *change);
void peer_release_name_ownership(Peer *peer, NameOwnership *ownership, NameChange *change);

int peer_add_match(Peer *peer, const char *rule_string);
int peer_remove_match(Peer *peer, const char *rule_string);
int peer_become_monitor(Peer *peer, MatchOwner *owner);
void peer_stop_monitor(Peer *peer);
void peer_flush_matches(Peer *peer);

int peer_queue_unicast(PolicySnapshot *sender_policy, NameSet *sender_names, ReplyOwner *sender_replies, User *sender_user, uint64_t sender_id, Peer *receiver, Message *message);
int peer_queue_reply(Peer *sender, const char *destination, uint32_t reply_serial, Message *message);

void peer_registry_init(PeerRegistry *registry);
void peer_registry_deinit(PeerRegistry *registry);
void peer_registry_flush(PeerRegistry *registry);
Peer *peer_registry_find_peer(PeerRegistry *registry, uint64_t id);

static inline bool peer_is_registered(Peer *peer) {
        return peer->registered;
}

static inline bool peer_is_monitor(Peer *peer) {
        return peer->monitor;
}

C_DEFINE_CLEANUP(Peer *, peer_free);
