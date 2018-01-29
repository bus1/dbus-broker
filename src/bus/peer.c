/*
 * Peers
 */

#include <c-macro.h>
#include <c-rbtree.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include "bus/bus.h"
#include "bus/driver.h"
#include "bus/match.h"
#include "bus/name.h"
#include "bus/peer.h"
#include "bus/policy.h"
#include "bus/reply.h"
#include "dbus/address.h"
#include "dbus/message.h"
#include "dbus/protocol.h"
#include "dbus/socket.h"
#include "util/dispatch.h"
#include "util/error.h"
#include "util/fdlist.h"
#include "util/log.h"
#include "util/metrics.h"
#include "util/sockopt.h"
#include "util/user.h"

static int peer_dispatch_connection(Peer *peer, uint32_t events) {
        int r;

        if (!events)
                return 0;

        r = connection_dispatch(&peer->connection, events);
        if (r)
                return error_fold(r);

        for (;;) {
                _c_cleanup_(message_unrefp) Message *m = NULL;

                r = connection_dequeue(&peer->connection, &m);
                if (r || !m) {
                        if (r == CONNECTION_E_EOF)
                                return PEER_E_EOF;

                        return error_fold(r);
                }

                metrics_sample_start(&peer->bus->metrics);
                r = driver_dispatch(peer, m);
                metrics_sample_end(&peer->bus->metrics);
                if (r) {
                        if (r == DRIVER_E_PROTOCOL_VIOLATION)
                                return PEER_E_PROTOCOL_VIOLATION;

                        return error_fold(r);
                }
        }

        return 0;
}

int peer_dispatch(DispatchFile *file) {
        Peer *peer = c_container_of(file, Peer, connection.socket_file);
        static const uint32_t interest[] = { EPOLLIN | EPOLLHUP, EPOLLOUT };
        size_t i;
        int r;

        /*
         * Usually, we would just call
         * peer_dispatch_connection(peer, dispatch_file_events(file)) here.
         * However, a very common scenario is to dispatch D-Bus driver calls.
         * Those calls fetch an incoming message from a peer, handle it and
         * then immediately queue a reply. In those cases we want EPOLLOUT
         * to be handled late. Hence, rather than dispatching the connection
         * in one go, we rather split it into two:
         *
         *     peer_dispatch_connection(peer, EPOLLIN | EPOLLHUP);
         *     peer_dispatch_connection(peer, EPOLLOUT);
         *
         * This makes sure to first handle all the incoming messages, then the
         * outgointg messages.
         *
         * Note that it is not enough to simply delay the call to
         * connection_dispatch(EPOLLOUT). The socket API requires you to loop
         * over connection_dequeue() after *ANY* call to the dispatcher. This
         * is, because the dequeue function is considered to be the event
         * handler, and as such the only function that performs forward
         * progress on the socket.
         *
         * Furthermore, note that we must not cache the events but rather query
         * dispatch_file_events(), since the connection handler might select or
         * deselect events we want to handle.
         *
         * Lastly, the connection API explicitly allows splitting the events.
         * There is no requirement to provide them in-order.
         */
        for (i = 0; i < C_ARRAY_SIZE(interest); ++i) {
                r = peer_dispatch_connection(peer, dispatch_file_events(file) & interest[i]);
                if (r)
                        break;
        }

        if (r) {
                if (r == PEER_E_EOF) {
                        metrics_sample_start(&peer->bus->metrics);
                        r = driver_goodbye(peer, false);
                        metrics_sample_end(&peer->bus->metrics);
                        if (r)
                                return error_fold(r);

                        connection_shutdown(&peer->connection);
                } else if (r == PEER_E_PROTOCOL_VIOLATION) {
                        connection_close(&peer->connection);

                        metrics_sample_start(&peer->bus->metrics);
                        r = driver_goodbye(peer, false);
                        metrics_sample_end(&peer->bus->metrics);
                        if (r)
                                return error_fold(r);
                } else {
                        return error_fold(r);
                }

                if (!connection_is_running(&peer->connection))
                        peer_free(peer);
        }

        /* Careful: @peer might be deallocated here */

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
                     PolicyRegistry *policy,
                     const char guid[],
                     DispatchContext *dispatcher,
                     int fd) {
        _c_cleanup_(peer_freep) Peer *peer = NULL;
        _c_cleanup_(user_unrefp) User *user = NULL;
        _c_cleanup_(c_freep) gid_t *gids = NULL;
        _c_cleanup_(c_freep) char *seclabel = NULL;
        CRBNode **slot, *parent;
        size_t n_seclabel, n_gids = 0;
        struct ucred ucred;
        socklen_t socklen = sizeof(ucred);
        int r;

        r = getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &ucred, &socklen);
        if (r < 0)
                return error_origin(-errno);

        r = user_registry_ref_user(&bus->users, &user, ucred.uid);
        if (r < 0)
                return error_fold(r);

        r = sockopt_get_peersec(fd, &seclabel, &n_seclabel);
        if (r < 0)
                return error_trace(r);

        r = sockopt_get_peergroups(fd, ucred.uid, ucred.gid, &gids, &n_gids);
        if (r)
                return error_trace(r);

        peer = calloc(1, sizeof(*peer));
        if (!peer)
                return error_origin(-ENOMEM);
        *peer = (Peer)PEER_INIT(*peer);

        peer->bus = bus;
        peer->user = user;
        user = NULL;
        peer->pid = ucred.pid;
        peer->gids = gids;
        gids = NULL;
        peer->n_gids = n_gids;
        peer->seclabel = seclabel;
        seclabel = NULL;
        peer->n_seclabel = n_seclabel;

        r = user_charge(user, &peer->charges[0], NULL, USER_SLOT_BYTES, sizeof(Peer));
        r = r ?: user_charge(user, &peer->charges[1], NULL, USER_SLOT_FDS, 1);
        r = r ?: user_charge(user, &peer->charges[2], NULL, USER_SLOT_OBJECTS, 1);
        if (r) {
                if (r == USER_E_QUOTA)
                        return PEER_E_QUOTA;

                return error_fold(r);
        }

        r = policy_snapshot_new(&peer->policy, policy, peer->seclabel, ucred.uid, peer->gids, peer->n_gids);
        if (r)
                return error_fold(r);

        r = policy_snapshot_check_connect(peer->policy);
        if (r)
                return (r == POLICY_E_ACCESS_DENIED) ? PEER_E_CONNECTION_REFUSED : error_fold(r);

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

        c_rbnode_unlink(&peer->registry_node);
        c_list_unlink(&peer->listener_link);

        fd = peer->connection.socket.fd;

        reply_owner_deinit(&peer->owned_replies);
        reply_registry_deinit(&peer->replies);
        match_owner_deinit(&peer->owned_matches);
        match_registry_deinit(&peer->name_owner_changed_matches);
        match_registry_deinit(&peer->sender_matches);
        name_owner_deinit(&peer->owned_names);
        policy_snapshot_free(peer->policy);
        connection_deinit(&peer->connection);
        user_unref(peer->user);
        user_charge_deinit(&peer->charges[2]);
        user_charge_deinit(&peer->charges[1]);
        user_charge_deinit(&peer->charges[0]);
        free(peer->seclabel);
        free(peer->gids);
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

bool peer_is_privileged(Peer *peer) {
        if (peer->user->uid == 0)
                return true;

        if (peer->user->uid == peer->bus->user->uid)
                return true;

        return false;
}

int peer_request_name(Peer *peer, const char *name, uint32_t flags, NameChange *change) {
        int r;

        if (!strcmp(name, "org.freedesktop.DBus"))
                return PEER_E_NAME_RESERVED;

        if (name[0] == ':')
                return PEER_E_NAME_UNIQUE;

        /* XXX: refuse invalid names */

        r = policy_snapshot_check_own(peer->policy, name);
        if (r) {
                if (r == POLICY_E_ACCESS_DENIED)
                        return PEER_E_NAME_REFUSED;

                return error_fold(r);
        }

        r = name_registry_request_name(&peer->bus->names,
                                       &peer->owned_names,
                                       peer->user,
                                       name,
                                       flags,
                                       change);
        if (r == NAME_E_QUOTA)
                return PEER_E_QUOTA;
        else if (r == NAME_E_ALREADY_OWNER)
                return PEER_E_NAME_ALREADY_OWNER;
        else if (r == NAME_E_IN_QUEUE)
                return PEER_E_NAME_IN_QUEUE;
        else if (r == NAME_E_EXISTS)
                return PEER_E_NAME_EXISTS;
        else if (r)
                return error_fold(r);

        return 0;
}

int peer_release_name(Peer *peer, const char *name, NameChange *change) {
        int r;

        if (!strcmp(name, "org.freedesktop.DBus"))
                return PEER_E_NAME_RESERVED;

        if (name[0] == ':')
                return PEER_E_NAME_UNIQUE;

        /* XXX: refuse invalid names */

        r = name_registry_release_name(&peer->bus->names, &peer->owned_names, name, change);
        if (r == NAME_E_NOT_FOUND)
                return PEER_E_NAME_NOT_FOUND;
        else if (r == NAME_E_NOT_OWNER)
                return PEER_E_NAME_NOT_OWNER;
        else if (r)
                return error_fold(r);

        return 0;
}

void peer_release_name_ownership(Peer *peer, NameOwnership *ownership, NameChange *change) {
        name_ownership_release(ownership, change);
}

static int peer_link_match(Peer *peer, MatchRule *rule, bool monitor) {
        Address addr;
        Peer *sender, *owner;
        int r;

        if (!rule->keys.sender) {
                match_rule_link(rule, &peer->bus->wildcard_matches, monitor);
        } else if (strcmp(rule->keys.sender, "org.freedesktop.DBus") == 0) {
                if (rule->keys.filter.member &&
                    strcmp(rule->keys.filter.member, "NameOwnerChanged") == 0 &&
                    rule->keys.filter.args[0] &&
                    strcmp(rule->keys.filter.args[0], "org.freedesktop.DBus") != 0) {
                        /*
                         * This rule is a subscription to NameOwnerChanged signals on a specific name,
                         * link it on the name or peer that may trigger it.
                         */
                        address_from_string(&addr, rule->keys.filter.args[0]);
                        switch (addr.type) {
                        case ADDRESS_TYPE_ID: {
                                owner = peer_registry_find_peer(&peer->bus->peers, addr.id);
                                if (owner) {
                                        match_rule_link(rule, &owner->name_owner_changed_matches, monitor);
                                } else if (addr.id >= peer->bus->peers.ids) {
                                        /*
                                         * This peer does not yet exist, but it could
                                         * appear, keep it with the wildcards. It will
                                         * stay there even if the peer later appears.
                                         * This works and is meant for compatibility.
                                         * It does not perform nicely, but there is
                                         * also no reason to ever guess the ID of a
                                         * forthcoming peer, so this is most likely
                                         * a bug in a client.
                                         */
                                        match_rule_link(rule, &peer->bus->sender_matches, monitor);
                                } else {
                                        /*
                                         * The peer has already disconnected and will
                                         * never reappear, since the ID allocator is
                                         * already beyond the ID.
                                         * We can simply skip linking the rule, since
                                         * it can never have an effect. It stays linked
                                         * in its owner, though, so we don't lose
                                         * track.
                                         */
                                }
                                break;
                        }
                        case ADDRESS_TYPE_NAME:
                        case ADDRESS_TYPE_OTHER: {
                                _c_cleanup_(name_unrefp) Name *name = NULL;

                                r = name_registry_ref_name(&peer->bus->names, &name, rule->keys.filter.args[0]);
                                if (r)
                                        return error_fold(r);

                                match_rule_link(rule, &name->name_owner_changed_matches, monitor);
                                name_ref(name); /* this reference must be explicitly released */
                                break;
                        }
                        default:
                                return error_origin(-ENOTRECOVERABLE);
                        }
                } else {
                        /*
                         * This should be a wildcard match on all NameOwnerChanged signals, we also
                         * install other (unexpected) matches here, they will always be false negatives
                         * but for the sake of simplicity we do not attempt to optimize them away.
                         */
                        match_rule_link(rule, &peer->bus->sender_matches, monitor);
                }
        } else {
                address_from_string(&addr, rule->keys.sender);
                switch (addr.type) {
                case ADDRESS_TYPE_ID: {
                        sender = peer_registry_find_peer(&peer->bus->peers, addr.id);
                        if (sender) {
                                match_rule_link(rule, &sender->sender_matches, monitor);
                        } else if (addr.id >= peer->bus->peers.ids) {
                                /*
                                 * This peer does not yet exist, by the same
                                 * reasoning as above, keep it as a wildcard
                                 * match.
                                 */
                                rule->keys.filter.sender = addr.id;
                                match_rule_link(rule, &peer->bus->wildcard_matches, monitor);
                        } else {
                                /*
                                 * The peer has already disconnected and will
                                 * never reappear, don't link it, by the same
                                 * logic as above.
                                 */
                        }
                        break;
                }
                case ADDRESS_TYPE_NAME:
                case ADDRESS_TYPE_OTHER: {
                        /*
                         * XXX: dbus-daemon rejects any match on invalid names.
                         *      However, we cannot do this here as our caller
                         *      does not expect this. This needs some further
                         *      restructuring.
                         */
                        _c_cleanup_(name_unrefp) Name *name = NULL;

                        r = name_registry_ref_name(&peer->bus->names, &name, rule->keys.sender);
                        if (r)
                                return error_fold(r);

                        match_rule_link(rule, &name->sender_matches, monitor);
                        name_ref(name); /* this reference must be explicitly released */
                        break;
                }
                default:
                        return error_origin(-ENOTRECOVERABLE);
                }
        }

        return 0;
}

int peer_add_match(Peer *peer, const char *rule_string) {
        _c_cleanup_(match_rule_user_unrefp) MatchRule *rule = NULL;
        int r;

        r = match_owner_ref_rule(&peer->owned_matches, &rule, peer->user, rule_string);
        if (r) {
                if (r == MATCH_E_QUOTA)
                        return PEER_E_QUOTA;
                else if (r == MATCH_E_INVALID)
                        return PEER_E_MATCH_INVALID;
                else
                        return error_fold(r);
        }

        r = peer_link_match(peer, rule, false);
        if (r)
                return error_trace(r);

        rule = NULL;

        return 0;
}

static Name *peer_match_rule_to_name(MatchRule *rule) {
        if (!rule->keys.sender)
                return NULL;
        /*
         * A match can be associated with a name in two cases:
         *  - if it is a NameOwnerChanged subscription on the name, or
         *  - if it is a sender match on the name.
         */
        if (strcmp(rule->keys.sender, "org.freedesktop.DBus") == 0) {
                if (rule->keys.filter.member && strcmp(rule->keys.filter.member, "NameOwnerChanged") == 0 &&
                    rule->keys.filter.args[0] && strcmp(rule->keys.filter.args[0], "org.freedesktop.DBus") != 0 &&
                    rule->keys.filter.args[0][0] != ':')
                        return c_container_of(rule->registry, Name, name_owner_changed_matches);
        } else if (rule->keys.sender[0] != ':') {
                return c_container_of(rule->registry, Name, sender_matches);
        }

        return NULL;
}

int peer_remove_match(Peer *peer, const char *rule_string) {
        _c_cleanup_(name_unrefp) Name *name = NULL;
        MatchRule *rule;
        int r;

        r = match_owner_find_rule(&peer->owned_matches, &rule, rule_string);
        if (r == MATCH_E_INVALID)
                return PEER_E_MATCH_INVALID;
        else if (r)
                return error_fold(r);
        else if (!rule)
                return PEER_E_MATCH_NOT_FOUND;

        /*
         * A match may pin a name, in which case first get the name from the
         * rule, then unref the rule, before finally unreffing the name.
         */
        name = peer_match_rule_to_name(rule);

        match_rule_user_unref(rule);

        return 0;
}

int peer_become_monitor(Peer *peer, MatchOwner *owned_matches) {
        MatchRule *rule;
        int r, poison = 0;

        assert(!peer->registered);
        assert(!peer->monitor);
        assert(c_rbtree_is_empty(&peer->owned_matches.rule_tree));

        /* only fatal errors may occur after this point */
        match_owner_move(&peer->owned_matches, owned_matches);

        c_rbtree_for_each_entry(rule, &peer->owned_matches.rule_tree, owner_node) {

                rule->owner = &peer->owned_matches;

                r = peer_link_match(peer, rule, true);
                if (r && !poison)
                        poison = error_trace(r);
        }

        if (poison)
                /* a fatal error occured, the peer was modified, but still consistent */
                return poison;

        peer->monitor = true;
        ++peer->bus->n_monitors;

        return 0;
}

void peer_stop_monitor(Peer *peer) {
        assert(!peer->registered);
        assert(peer->monitor);
        assert(c_rbtree_is_empty(&peer->owned_matches.rule_tree));

        peer->monitor = false;
        --peer->bus->n_monitors;
}

void peer_flush_matches(Peer *peer) {
        CRBNode *node;

        while ((node = peer->owned_matches.rule_tree.root)) {
                _c_cleanup_(name_unrefp) Name *name = NULL;
                MatchRule *rule = c_container_of(node, MatchRule, owner_node);

                /*
                 * As above, a match may pin a name.
                 */
                name = peer_match_rule_to_name(rule);

                match_rule_user_unref(rule);
        }
}

int peer_queue_call(PolicySnapshot *sender_policy, NameSet *sender_names, MatchRegistry *sender_matches, ReplyOwner *sender_replies, User *sender_user, uint64_t sender_id, Peer *receiver, Message *message) {
        _c_cleanup_(reply_slot_freep) ReplySlot *slot = NULL;
        NameSet receiver_names = NAME_SET_INIT_FROM_OWNER(&receiver->owned_names);
        uint32_t serial;
        int r;

        serial = message_read_serial(message);

        if (sender_replies && serial) {
                r = reply_slot_new(&slot, &receiver->replies, sender_replies,
                                   receiver->user, sender_user, sender_id, serial);
                if (r == REPLY_E_EXISTS)
                        return PEER_E_EXPECTED_REPLY_EXISTS;
                else if (r == REPLY_E_QUOTA)
                        return PEER_E_QUOTA;
                else if (r)
                        return error_fold(r);
        }

        r = policy_snapshot_check_receive(receiver->policy,
                                          sender_names,
                                          message->metadata.fields.interface,
                                          message->metadata.fields.member,
                                          message->metadata.fields.path,
                                          message->header->type);
        if (r) {
                if (r == POLICY_E_ACCESS_DENIED) {
                        log_append_here(receiver->bus->log, LOG_WARNING, 0);
                        r = bus_log_commit_policy_receive(receiver->bus, receiver->id, sender_id, message);
                        if (r)
                                return error_fold(r);

                        return PEER_E_RECEIVE_DENIED;
                }

                return error_fold(r);
        }

        r = policy_snapshot_check_send(sender_policy,
                                       receiver->seclabel,
                                       &receiver_names,
                                       message->metadata.fields.interface,
                                       message->metadata.fields.member,
                                       message->metadata.fields.path,
                                       message->header->type);
        if (r) {
                if (r == POLICY_E_ACCESS_DENIED) {
                        log_append_here(receiver->bus->log, LOG_WARNING, 0);
                        r = bus_log_commit_policy_send(receiver->bus, sender_id, receiver->id, message);
                        if (r)
                                return error_fold(r);

                        return PEER_E_SEND_DENIED;
                }

                return error_fold(r);
        }

        r = connection_queue(&receiver->connection, sender_user, message);
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
        Address addr;
        int r;

        address_from_string(&addr, destination);
        if (addr.type != ADDRESS_TYPE_ID)
                return PEER_E_UNEXPECTED_REPLY;

        slot = reply_slot_get_by_id(&sender->replies, addr.id, reply_serial);
        if (!slot)
                return PEER_E_UNEXPECTED_REPLY;

        receiver = c_container_of(slot->owner, Peer, owned_replies);

        r = connection_queue(&receiver->connection, NULL, message);
        if (r) {
                if (r == CONNECTION_E_QUOTA)
                        connection_shutdown(&receiver->connection);
                else
                        return error_fold(r);
        }

        return 0;
}

static int peer_broadcast_to_matches(PolicySnapshot *sender_policy, NameSet *sender_names, MatchRegistry *matches, MatchFilter *filter, uint64_t transaction_id, Message *message) {
        MatchRule *rule;
        int r;

        for (rule = match_rule_next_match(matches, NULL, filter); rule; rule = match_rule_next_match(matches, rule, filter)) {
                Peer *receiver = c_container_of(rule->owner, Peer, owned_matches);
                NameSet receiver_names = NAME_SET_INIT_FROM_OWNER(&receiver->owned_names);

                /* exclude the destination from broadcasts */
                if (filter->destination == receiver->id)
                        continue;
                if (transaction_id <= receiver->transaction_id)
                        continue;

                receiver->transaction_id = c_max(transaction_id, receiver->transaction_id);

                if (sender_policy) {
                        r = policy_snapshot_check_send(sender_policy,
                                                       receiver->seclabel,
                                                       &receiver_names,
                                                       message->metadata.fields.interface,
                                                       message->metadata.fields.member,
                                                       message->metadata.fields.path,
                                                       message->header->type);
                        if (r) {
                                if (r == POLICY_E_ACCESS_DENIED)
                                        continue;

                                return error_fold(r);
                        }
                }

                r = policy_snapshot_check_receive(receiver->policy,
                                                  sender_names,
                                                  message->metadata.fields.interface,
                                                  message->metadata.fields.member,
                                                  message->metadata.fields.path,
                                                  message->header->type);
                if (r) {
                        if (r == POLICY_E_ACCESS_DENIED)
                                continue;

                        return error_fold(r);
                }

                r = connection_queue(&receiver->connection, NULL, message);
                if (r) {
                        if (r == CONNECTION_E_QUOTA)
                                connection_shutdown(&receiver->connection);
                        else
                                return error_fold(r);
                }
        }

        return 0;
}

int peer_broadcast(PolicySnapshot *sender_policy, NameSet *sender_names, MatchRegistry *matches, uint64_t sender_id, Peer *destination, Bus *bus, MatchFilter *filter, Message *message) {
        MatchFilter fallback_filter = MATCH_FILTER_INIT;
        int r;

        if (!filter) {
                filter = &fallback_filter;

                filter->type = message->metadata.header.type;
                filter->sender = sender_id;
                filter->destination = destination ? destination->id : ADDRESS_ID_INVALID;
                filter->interface = message->metadata.fields.interface;
                filter->member = message->metadata.fields.member,
                filter->path = message->metadata.fields.path;

                for (size_t i = 0; i < 64; ++i) {
                        if (message->metadata.args[i].element == 's') {
                                filter->args[i] = message->metadata.args[i].value;
                                filter->argpaths[i] = message->metadata.args[i].value;
                        } else if (message->metadata.args[i].element == 'o') {
                                filter->argpaths[i] = message->metadata.args[i].value;
                        }
                }
        }

        /* start a new transaction, to avoid duplicates */
        ++bus->transaction_ids;

        r = peer_broadcast_to_matches(sender_policy, sender_names, &bus->wildcard_matches, filter, bus->transaction_ids, message);
        if (r)
                return error_trace(r);

        if (matches) {
                r = peer_broadcast_to_matches(sender_policy, sender_names, matches, filter, bus->transaction_ids, message);
                if (r)
                        return error_trace(r);
        }

        if (sender_names) {
                NameOwner *owner;
                NameOwnership *ownership;
                NameSnapshot *snapshot;

                switch (sender_names->type) {
                case NAME_SET_TYPE_OWNER:
                        owner = sender_names->owner;

                        c_rbtree_for_each_entry(ownership, &owner->ownership_tree, owner_node) {
                                if (!name_ownership_is_primary(ownership))
                                        continue;

                                r = peer_broadcast_to_matches(sender_policy, sender_names, &ownership->name->sender_matches, filter, bus->transaction_ids, message);
                                if (r)
                                        return error_trace(r);
                        }
                        break;
                case NAME_SET_TYPE_SNAPSHOT:
                        snapshot = sender_names->snapshot;

                        for (size_t i = 0; i < snapshot->n_names; ++i) {
                                r = peer_broadcast_to_matches(sender_policy, sender_names, &snapshot->names[i]->sender_matches, filter, bus->transaction_ids, message);
                                if (r)
                                        return error_trace(r);
                        }
                        break;
                default:
                        return error_origin(-ENOTRECOVERABLE);
                }
        } else {
                /* sent from the driver */
                r = peer_broadcast_to_matches(NULL, NULL, &bus->sender_matches, filter, bus->transaction_ids, message);
                if (r)
                        return error_trace(r);
        }

        return 0;
}

void peer_registry_init(PeerRegistry *registry) {
        *registry = (PeerRegistry)PEER_REGISTRY_INIT;
}

void peer_registry_deinit(PeerRegistry *registry) {
        assert(c_rbtree_is_empty(&registry->peer_tree));
        registry->ids = 0;
}

void peer_registry_flush(PeerRegistry *registry) {
        Peer *peer, *safe;
        int r;

        c_rbtree_for_each_entry_safe_postorder_unlink(peer, safe, &registry->peer_tree, registry_node) {
                r = driver_goodbye(peer, true);
                assert(!r); /* can not fail in silent mode */
                peer_free(peer);
        }
}

Peer *peer_registry_find_peer(PeerRegistry *registry, uint64_t id) {
        Peer *peer;

        peer = c_rbtree_find_entry(&registry->peer_tree, peer_compare, &id, Peer, registry_node);

        return peer && peer->registered ? peer : NULL;
}
