/*
 * Peers
 */

#include <c-macro.h>
#include <c-rbtree.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include "bus.h"
#include "dbus/message.h"
#include "dbus/protocol.h"
#include "dbus/socket.h"
#include "dbus/unique-name.h"
#include "driver.h"
#include "match.h"
#include "name.h"
#include "peer.h"
#include "reply.h"
#include "util/dispatch.h"
#include "util/error.h"
#include "util/fdlist.h"
#include "util/metrics.h"
#include "util/user.h"

int peer_dispatch(DispatchFile *file, uint32_t mask) {
        Peer *peer = c_container_of(file, Peer, connection.socket_file);
        int r;

        if (dispatch_file_is_ready(file, EPOLLIN)) {
                r = connection_dispatch(&peer->connection, EPOLLIN);
                if (r)
                        return error_fold(r);
        }

        if (dispatch_file_is_ready(file, EPOLLHUP)) {
                r = connection_dispatch(&peer->connection, EPOLLHUP);
                if (r)
                        return error_fold(r);
        }

        for (;;) {
                _c_cleanup_(message_unrefp) Message *m = NULL;

                r = connection_dequeue(&peer->connection, &m);
                if (r) {
                        if (r == CONNECTION_E_EOF) {
                                r = driver_goodbye(peer, false);
                                if (r)
                                        return error_fold(r);
                                connection_shutdown(&peer->connection);
                        } else if (r == CONNECTION_E_RESET) {
                                r = driver_goodbye(peer, false);
                                if (r)
                                        return error_fold(r);
                        } else {
                                return error_fold(r);
                        }
                }
                if (!m) {
                        break;
                }

                metrics_sample_start(&peer->bus->metrics);
                r = driver_dispatch(peer, m);
                metrics_sample_end(&peer->bus->metrics);
                if (r)
                        return error_fold(r);
        }

        if (dispatch_file_is_ready(file, EPOLLOUT)) {
                r = connection_dispatch(&peer->connection, EPOLLOUT);
                if (r)
                        return error_fold(r);
        }

        if (!connection_is_running(&peer->connection))
                peer_free(peer);

        return 0;
}

static int peer_get_peersec(int fd, char **labelp, size_t *lenp) {
        _c_cleanup_(c_freep) char *label = NULL;
        char *l;
        socklen_t len = 1023;
        int r;

        label = malloc(len + 1);
        if (!label)
                return error_origin(-ENOMEM);

        for (;;) {
                r = getsockopt(fd, SOL_SOCKET, SO_PEERSEC, label, &len);
                if (r >= 0) {
                        label[len] = '\0';
                        *lenp = len;
                        *labelp = label;
                        label = NULL;
                        break;
                } else if (errno == ENOPROTOOPT) {
                        *lenp = 0;
                        *labelp = NULL;
                        break;
                } else if (errno != ERANGE)
                        return -errno;

                l = realloc(label, len + 1);
                if (!l)
                        return error_origin(-ENOMEM);

                label = l;
        }

        return 0;
}

static int peer_compare(CRBTree *tree, void *k, CRBNode *rb) {
        Peer *peer = c_container_of(rb, Peer, registry_node);
        uint64_t id = *(uint64_t*)k;

        if (id < peer->id)
                return -1;
        if (id > peer->id)
                return 1;

        return 0;
}

/**
 * peer_new() - XXX
 */
int peer_new_with_fd(Peer **peerp,
                     Bus *bus,
                     const char guid[],
                     DispatchContext *dispatcher,
                     int fd) {
        _c_cleanup_(peer_freep) Peer *peer = NULL;
        _c_cleanup_(user_unrefp) User *user = NULL;
        _c_cleanup_(c_freep) char *seclabel = NULL;
        CRBNode **slot, *parent;
        size_t n_seclabel;
        struct ucred ucred;
        socklen_t socklen = sizeof(ucred);
        int r;

        r = getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &ucred, &socklen);
        if (r < 0)
                return error_origin(-errno);

        r = connection_policy_check_allowed(&bus->policy_registry.connection_policy, ucred.uid);
        if (r) {
                if (r == POLICY_E_ACCESS_DENIED)
                        return PEER_E_CONNECTION_REFUSED;

                return error_fold(r);
        }

        r = user_registry_ref_user(&bus->users, &user, ucred.uid);
        if (r < 0)
                return error_fold(r);

        if (user->slots[USER_SLOT_PEERS].n < 1)
                return PEER_E_QUOTA;

        r = peer_get_peersec(fd, &seclabel, &n_seclabel);
        if (r < 0)
                return error_trace(r);

        peer = calloc(1, sizeof(*peer));
        if (!peer)
                return error_origin(-ENOMEM);

        --user->slots[USER_SLOT_PEERS].n;

        peer->bus = bus;
        peer->connection = (Connection)CONNECTION_NULL(peer->connection);
        c_rbnode_init(&peer->registry_node);
        peer->user = user;
        user = NULL;
        peer->pid = ucred.pid;
        peer->seclabel = seclabel;
        seclabel = NULL;
        peer->n_seclabel = n_seclabel;
        policy_init(&peer->policy);
        peer->owned_names = (NameOwner){};
        match_registry_init(&peer->matches);
        match_owner_init(&peer->owned_matches);
        reply_registry_init(&peer->replies_outgoing);
        peer->owned_replies = (ReplyOwner)REPLY_OWNER_INIT(peer->owned_replies);

        r = connection_init_server(&peer->connection,
                                   dispatcher,
                                   peer_dispatch,
                                   peer->user,
                                   guid,
                                   fd);
        if (r < 0)
                return error_fold(r);

        peer->id = bus->peers.ids++;
        slot = c_rbtree_find_slot(&bus->peers.peer_tree, peer_compare, &peer->id, &parent);
        assert(slot); /* peer->id is guaranteed to be unique */
        c_rbtree_add(&bus->peers.peer_tree, parent, slot, &peer->registry_node);

        *peerp = peer;
        peer = NULL;
        return 0;
}

/**
 * peer_free() - XXX
 */
Peer *peer_free(Peer *peer) {
        int fd;

        if (!peer)
                return NULL;

        assert(!peer->registered);

        ++peer->user->slots[USER_SLOT_PEERS].n;

        c_rbtree_remove_init(&peer->bus->peers.peer_tree, &peer->registry_node);

        fd = peer->connection.socket.fd;

        reply_owner_deinit(&peer->owned_replies);
        reply_registry_deinit(&peer->replies_outgoing);
        match_owner_deinit(&peer->owned_matches);
        match_registry_deinit(&peer->matches);
        name_owner_deinit(&peer->owned_names);
        policy_deinit(&peer->policy);
        connection_deinit(&peer->connection);
        user_unref(peer->user);
        free(peer->seclabel);
        free(peer);

        close(fd);

        return NULL;
}

int peer_spawn(Peer *peer) {
        return error_fold(connection_open(&peer->connection));
}

void peer_register(Peer *peer) {
        assert(!peer->registered);
        assert(!peer->monitor);

        peer->registered = true;
}

void peer_unregister(Peer *peer) {
        assert(peer->registered);
        assert(!peer->monitor);

        peer->registered = false;
}

int peer_request_name(Peer *peer, const char *name, uint32_t flags, NameChange *change) {
        int r;

        if (peer->user->slots[USER_SLOT_NAMES].n == 0)
                return PEER_E_QUOTA;

        if (!strcmp(name, "org.freedesktop.DBus"))
                return PEER_E_NAME_RESERVED;

        if (name[0] == ':')
                return PEER_E_NAME_UNIQUE;

        /* XXX: refuse invalid names */

        r = ownership_policy_check_allowed(&peer->policy.ownership_policy, name);
        if (r) {
                if (r == POLICY_E_ACCESS_DENIED)
                        return PEER_E_NAME_REFUSED;

                return error_fold(r);
        }

        r = name_registry_request_name(&peer->bus->names, &peer->owned_names, name, flags, change);
        switch (r) {
        case 0:
                return PEER_E_NAME_ALREADY_OWNER;
        case NAME_E_OWNER_NEW:
                --peer->user->slots[USER_SLOT_NAMES].n;
                /* fall-through */
        case NAME_E_OWNER_UPDATED:
                return 0;
        case NAME_E_IN_QUEUE_NEW:
                --peer->user->slots[USER_SLOT_NAMES].n;
                /* fall-through */
        case NAME_E_IN_QUEUE_UPDATED:
                return PEER_E_NAME_IN_QUEUE;
        case NAME_E_EXISTS:
                return PEER_E_NAME_EXISTS;
        }

        return error_fold(r);
}

int peer_release_name(Peer *peer, const char *name, NameChange *change) {
        int r;

        if (!strcmp(name, "org.freedesktop.DBus"))
                return PEER_E_NAME_RESERVED;

        if (name[0] == ':')
                return PEER_E_NAME_UNIQUE;

        /* XXX: refuse invalid names */

        r = name_registry_release_name(&peer->bus->names, &peer->owned_names, name, change);
        if (!r) {
                ++peer->user->slots[USER_SLOT_NAMES].n;
                return 0;
        } else if (r == NAME_E_NOT_FOUND) {
                return PEER_E_NAME_NOT_FOUND;
        } else if (r == NAME_E_NOT_OWNER) {
                return PEER_E_NAME_NOT_OWNER;
        } else {
                return error_fold(r);
        }

}

void peer_release_name_ownership(Peer *peer, NameOwnership *ownership, NameChange *change) {
        name_ownership_release(ownership, change);
        ++peer->user->slots[USER_SLOT_NAMES].n;
}

static int peer_link_match(Peer *peer, MatchRule *rule) {
        int r;

        if (!rule->keys.sender) {
                match_rule_link(rule, &peer->bus->wildcard_matches);
        } else if (*rule->keys.sender == ':') {
                Peer *sender;
                uint64_t id;

                r = unique_name_to_id(rule->keys.sender, &id);
                if (r) {
                        if (r < 0)
                                return error_fold(r);
                        /* got a valid unique name that is not in our namespace */
                } else {
                        sender = peer_registry_find_peer(&peer->bus->peers, id);
                        if (sender) {
                                match_rule_link(rule, &sender->matches);
                        } else if (id >= peer->bus->peers.ids) {
                                /* this peer does not yet exist, but it could appear, keep it
                                 * with the wildcards. */
                                rule->keys.filter.sender = id;
                                match_rule_link(rule, &peer->bus->wildcard_matches);
                        }

                        /* the peer has already disconnected and will never reappear */
                }
        } else if (strcmp(rule->keys.sender, "org.freedesktop.DBus") == 0) {
                match_rule_link(rule, &peer->bus->driver_matches);
        } else {
                _c_cleanup_(name_unrefp) Name *name = NULL;

                r = name_registry_ref_name(&peer->bus->names, &name, rule->keys.sender);
                if (r)
                        return error_fold(r);

                match_rule_link(rule, &name->matches);
                name_ref(name); /* this reference must be explicitly released */
        }

        return 0;
}

int peer_add_match(Peer *peer, const char *rule_string, bool force_eavesdrop) {
        _c_cleanup_(match_rule_user_unrefp) MatchRule *rule = NULL;
        int r;

        if (peer->user->slots[USER_SLOT_MATCHES].n == 0)
                return PEER_E_QUOTA;

        r = match_owner_ref_rule(&peer->owned_matches, &rule, rule_string);
        if (r) {
                if (r == MATCH_E_INVALID)
                        return PEER_E_MATCH_INVALID;
                else
                        return error_fold(r);
        }

        if (force_eavesdrop)
                rule->keys.eavesdrop = true;

        r = peer_link_match(peer, rule);
        if (r)
                return error_trace(r);

        --peer->user->slots[USER_SLOT_MATCHES].n;
        rule = NULL;

        return 0;
}

int peer_remove_match(Peer *peer, const char *rule_string) {
        _c_cleanup_(name_unrefp) Name *name = NULL;
        MatchRule *rule;
        int r;

        r = match_rule_get(&rule, &peer->owned_matches, rule_string);
        if (r) {
                if (r == MATCH_E_NOT_FOUND)
                        return PEER_E_MATCH_NOT_FOUND;
                else if (r == MATCH_E_INVALID)
                        return PEER_E_MATCH_INVALID;
                else
                        return error_fold(r);
        }

        if (rule->keys.sender && *rule->keys.sender != ':' && strcmp(rule->keys.sender, "org.freedesktop.DBus") != 0)
                name = c_container_of(rule->registry, Name, matches);

        match_rule_user_unref(rule);
        ++peer->user->slots[USER_SLOT_MATCHES].n;

        return 0;
}

int peer_become_monitor(Peer *peer, MatchOwner *owned_matches) {
        MatchRule *rule;
        size_t n_matches = 0;
        int r, poison = 0;

        assert(!peer->registered);
        assert(!peer->monitor);
        assert(c_rbtree_is_empty(&peer->owned_matches.rule_tree));

        /* only fatal errors may occur after this point */
        peer->owned_matches = *owned_matches;
        *owned_matches = (MatchOwner){};

        c_rbtree_for_each_entry(rule, &peer->owned_matches.rule_tree, owner_node) {

                rule->keys.eavesdrop = true;
                rule->owner = &peer->owned_matches;

                r = peer_link_match(peer, rule);
                if (r && !poison)
                        poison = error_trace(r);

                ++n_matches;
        }

        assert(n_matches <= peer->user->slots[USER_SLOT_MATCHES].n);
        peer->user->slots[USER_SLOT_MATCHES].n -= n_matches;

        if (poison)
                /* a fatal error occured, the peer was modified, but still consistent */
                return poison;

        peer->monitor = true;

        return 0;
}

void peer_flush_matches(Peer *peer) {
        CRBNode *node;

        while ((node = peer->owned_matches.rule_tree.root)) {
                _c_cleanup_(name_unrefp) Name *name = NULL;
                MatchRule *rule = c_container_of(node, MatchRule, owner_node);

                if (rule->keys.sender && *rule->keys.sender != ':' && strcmp(rule->keys.sender, "org.freedesktop.DBus") != 0)
                        name = c_container_of(rule->registry, Name, matches);

                match_rule_user_unref(rule);
                ++peer->user->slots[USER_SLOT_MATCHES].n;
        }
}

int peer_queue_call(Peer *receiver, Peer *sender, Message *message) {
        _c_cleanup_(reply_slot_freep) ReplySlot *slot = NULL;
        int r;

        if ((message->header->type == DBUS_MESSAGE_TYPE_METHOD_CALL) &&
            !(message->header->flags & DBUS_HEADER_FLAG_NO_REPLY_EXPECTED)) {
                r = reply_slot_new(&slot, &receiver->replies_outgoing, &sender->owned_replies, sender->id, message_read_serial(message));
                if (r == REPLY_E_EXISTS)
                        return PEER_E_EXPECTED_REPLY_EXISTS;
                else if (r)
                        return error_fold(r);
        }

        r = connection_queue(&receiver->connection, sender->user, 0, message);
        if (r) {
                if (CONNECTION_E_QUOTA)
                        return PEER_E_QUOTA;
                else
                        return error_fold(r);
        }

        slot = NULL;
        return 0;
}

int peer_queue_reply(Peer *sender, const char *destination, uint32_t reply_serial, Message *message) {
        _c_cleanup_(reply_slot_freep) ReplySlot *slot = NULL;
        Peer *receiver;
        uint64_t id;
        int r;

        r = unique_name_to_id(destination, &id);
        if (r) {
                if (r > 0)
                        return PEER_E_UNEXPECTED_REPLY;

                return error_fold(r);
        }

        slot = reply_slot_get_by_id(&sender->replies_outgoing, id, reply_serial);
        if (!slot)
                return PEER_E_UNEXPECTED_REPLY;

        receiver = c_container_of(slot->owner, Peer, owned_replies);

        r = connection_queue(&receiver->connection, NULL, 0, message);
        if (r) {
                if (r == CONNECTION_E_QUOTA)
                        connection_close(&receiver->connection);
                else
                        return error_fold(r);
        }

        return 0;
}

void peer_registry_init(PeerRegistry *registry) {
        c_rbtree_init(&registry->peer_tree);
        registry->ids = 0;
}

void peer_registry_deinit(PeerRegistry *registry) {
        assert(c_rbtree_is_empty(&registry->peer_tree));
        registry->ids = 0;
}

void peer_registry_flush(PeerRegistry *registry) {
        Peer *peer, *safe;
        int r;

        c_rbtree_for_each_entry_unlink(peer, safe, &registry->peer_tree, registry_node) {
                r = driver_goodbye(peer, true);
                assert(!r); /* can not fail in silent mode */
                connection_close(&peer->connection);
                peer_free(peer);
        }
}

Peer *peer_registry_find_peer(PeerRegistry *registry, uint64_t id) {
        Peer *peer;

        peer = c_rbtree_find_entry(&registry->peer_tree, peer_compare, &id, Peer, registry_node);

        return peer && peer->registered ? peer : NULL;
}
