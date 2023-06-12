/*
 * Peers
 */

#include <c-rbtree.h>
#include <c-stdaux.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include "broker/controller.h"
#include "bus/bus.h"
#include "bus/driver.h"
#include "bus/match.h"
#include "bus/name.h"
#include "bus/peer.h"
#include "bus/policy.h"
#include "bus/reply.h"
#include "catalog/catalog-ids.h"
#include "dbus/address.h"
#include "dbus/message.h"
#include "dbus/protocol.h"
#include "dbus/socket.h"
#include "util/dispatch.h"
#include "util/error.h"
#include "util/fdlist.h"
#include "util/log.h"
#include "util/metrics.h"
#include "util/serialize.h"
#include "util/sockopt.h"
#include "util/string.h"
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
                if (r == CONNECTION_E_EOF) {
                        return PEER_E_EOF;
                } else if (r) {
                        NameSet peer_names = NAME_SET_INIT_FROM_OWNER(&peer->owned_names);

                        if (r == CONNECTION_E_QUOTA) {
                                log_append_here(peer->bus->log, LOG_WARNING, 0, NULL);
                                bus_log_append_sender(peer->bus, peer->id, &peer_names, peer->policy->seclabel);

                                r = log_commitf(peer->bus->log, "Peer :1.%llu is being disconnected as it does not have the resources to perform an operation.",
                                                peer->id);
                                if (r)
                                        return error_fold(r);

                                return PEER_E_QUOTA;
                        } else if (r == CONNECTION_E_SASL_VIOLATION) {
                                log_append_here(peer->bus->log, LOG_WARNING, 0, DBUS_BROKER_CATALOG_PROTOCOL_VIOLATION);
                                bus_log_append_sender(peer->bus, peer->id, &peer_names, peer->policy->seclabel);

                                r = log_commitf(peer->bus->log, "Peer :1.%llu is being disconnected as it violated the SASL protocol.",
                                                peer->id);
                                if (r)
                                        return error_fold(r);

                                return PEER_E_PROTOCOL_VIOLATION;
                        } else if (r == CONNECTION_E_UNEXPECTED_FDS) {
                                log_append_here(peer->bus->log, LOG_WARNING, 0, DBUS_BROKER_CATALOG_PROTOCOL_VIOLATION);
                                bus_log_append_sender(peer->bus, peer->id, &peer_names, peer->policy->seclabel);

                                r = log_commitf(peer->bus->log, "Peer :1.%llu is being disconnected as it attempted to pass file descriptors without negotiating support for it.",
                                                peer->id);
                                if (r)
                                        return error_fold(r);

                                return PEER_E_PROTOCOL_VIOLATION;
                        }

                        return error_fold(r);
                } else if (!m) {
                        return 0;
                }

                r = message_parse_metadata(m);
                if (r) {
                        NameSet peer_names = NAME_SET_INIT_FROM_OWNER(&peer->owned_names);

                        if (r == MESSAGE_E_INVALID_HEADER) {
                                log_append_here(peer->bus->log, LOG_WARNING, 0, DBUS_BROKER_CATALOG_PROTOCOL_VIOLATION);
                                bus_log_append_sender(peer->bus, peer->id, &peer_names, peer->policy->seclabel);

                                r = log_commitf(peer->bus->log, "Peer :1.%llu is being disconnected as it sent a message with an invalid header.",
                                                peer->id);
                                if (r)
                                        return error_fold(r);

                                return PEER_E_PROTOCOL_VIOLATION;
                        } else if (r == MESSAGE_E_INVALID_BODY) {
                                log_append_here(peer->bus->log, LOG_WARNING, 0, DBUS_BROKER_CATALOG_PROTOCOL_VIOLATION);
                                bus_log_append_sender(peer->bus, peer->id, &peer_names, peer->policy->seclabel);

                                r = log_commitf(peer->bus->log, "Peer :1.%llu is being disconnected as it sent a message with an invalid body.",
                                                peer->id);
                                if (r)
                                        return error_fold(r);

                                return PEER_E_PROTOCOL_VIOLATION;
                        } else if (r == MESSAGE_E_MISSING_FDS) {
                                log_append_here(peer->bus->log, LOG_WARNING, 0, DBUS_BROKER_CATALOG_PROTOCOL_VIOLATION);
                                bus_log_append_sender(peer->bus, peer->id, &peer_names, peer->policy->seclabel);

                                r = log_commitf(peer->bus->log, "Peer :1.%llu is being disconnected as it passed fewer file descriptors than its header declared.",
                                                peer->id);
                                if (r)
                                        return error_fold(r);

                                return PEER_E_PROTOCOL_VIOLATION;
                        }

                        return error_fold(r);
                }

                message_stitch_sender(m, peer->id);

                metrics_sample_start(&peer->bus->metrics);
                r = driver_dispatch(peer, m);
                metrics_sample_end(&peer->bus->metrics);
                if (r) {
                        NameSet peer_names = NAME_SET_INIT_FROM_OWNER(&peer->owned_names);

                        if (r == DRIVER_E_PEER_NOT_REGISTERED) {
                                log_append_here(peer->bus->log, LOG_WARNING, 0, DBUS_BROKER_CATALOG_PROTOCOL_VIOLATION);
                                bus_log_append_sender(peer->bus, peer->id, &peer_names, peer->policy->seclabel);
                                message_log_append(m, peer->bus->log);

                                r = log_commitf(peer->bus->log, "Peer :1.%llu is being disconnected as it sent a message before calling Hello().",
                                                peer->id);
                                if (r)
                                        return error_fold(r);

                                return PEER_E_PROTOCOL_VIOLATION;
                        } else if (r == DRIVER_E_MONITOR_READ_ONLY) {
                                log_append_here(peer->bus->log, LOG_WARNING, 0, DBUS_BROKER_CATALOG_PROTOCOL_VIOLATION);
                                bus_log_append_sender(peer->bus, peer->id, &peer_names, peer->policy->seclabel);
                                message_log_append(m, peer->bus->log);

                                r = log_commitf(peer->bus->log, "Monitor :1.%llu is being disconnected as it attempted to send a message.",
                                                peer->id);
                                if (r)
                                        return error_fold(r);

                                return PEER_E_PROTOCOL_VIOLATION;
                        }

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
                } else if (r == PEER_E_QUOTA ||
                           r == PEER_E_PROTOCOL_VIOLATION) {
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
                     int fd,
                     int peer_id) {
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

        if (ucred.pid == getppid()) {
                r = user_registry_ref_user(&bus->users, &user, bus->user->uid);
        } else {
                r = user_registry_ref_user(&bus->users, &user, ucred.uid);
        }
        if (r < 0)
                return error_fold(r);

        r = sockopt_get_peersec(fd, &seclabel, &n_seclabel);
        if (r < 0)
                return error_trace(r);

        r = sockopt_get_peergroups(fd, bus->log, ucred.uid, ucred.gid, &gids, &n_gids);
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

        r = user_charge(peer->user, &peer->charges[0], NULL, USER_SLOT_BYTES, sizeof(Peer));
        r = r ?: user_charge(peer->user, &peer->charges[1], NULL, USER_SLOT_FDS, 1);
        r = r ?: user_charge(peer->user, &peer->charges[2], NULL, USER_SLOT_OBJECTS, 1);
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

        if (peer_id < 0)
                peer->id = bus->peers.ids++;
        else
                peer->id = peer_id;
        slot = c_rbtree_find_slot(&bus->peers.peer_tree, peer_compare, &peer->id, &parent);
        c_assert(slot); /* peer->id is guaranteed to be unique */
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

        c_assert(!peer->registered);

        c_rbnode_unlink(&peer->registry_node);
        c_list_unlink(&peer->listener_link);

        fd = peer->connection.socket.fd;

        reply_owner_deinit(&peer->owned_replies);
        reply_registry_deinit(&peer->replies);
        match_owner_deinit(&peer->owned_matches);
        rule_string_deinit(&peer->rule_string_list);
        match_registry_deinit(&peer->name_owner_changed_matches);
        match_registry_deinit(&peer->sender_matches);
        name_owner_deinit(&peer->owned_names);
        policy_snapshot_free(peer->policy);
        connection_deinit(&peer->connection);
        user_charge_deinit(&peer->charges[2]);
        user_charge_deinit(&peer->charges[1]);
        user_charge_deinit(&peer->charges[0]);
        free(peer->seclabel);
        free(peer->gids);
        user_unref(peer->user);
        free(peer);

        close(fd);

        return NULL;
}

int peer_spawn(Peer *peer) {
        return error_fold(connection_open(&peer->connection));
}

void peer_register(Peer *peer) {
        c_assert(!peer->monitor);

        peer->registered = true;
}

void peer_unregister(Peer *peer) {
        c_assert(peer->registered);
        c_assert(!peer->monitor);

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

        r = policy_snapshot_check_own(peer->policy, name);
        if (r) {
                if (r == POLICY_E_ACCESS_DENIED ||
                    r == POLICY_E_SELINUX_ACCESS_DENIED ||
                    r == POLICY_E_APPARMOR_ACCESS_DENIED)
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

static int peer_link_rule_string(Peer *peer, const char *rule_string) {
        RuleString *rs;

        rs = malloc(sizeof(RuleString));
        if (!rs)
                return error_origin(-ENOMEM);
        *rs = (RuleString)RULE_STRING_INIT(*rs);

        rs->rule_string = strdup(rule_string);
        if (!rs->rule_string)
                return error_origin(-ENOMEM);

        c_list_link_tail(&peer->rule_string_list, &rs->rule_string_link);
        return 0;
}

static int peer_link_match(Peer *peer, MatchRule *rule, bool monitor) {
        Address addr;
        Peer *sender, *owner;
        int r;

        if (!rule->keys.sender) {
                r = match_rule_link(rule, &peer->bus->wildcard_matches, monitor);
                if (r)
                        return error_fold(r);
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
                                        r = match_rule_link(rule, &owner->name_owner_changed_matches, monitor);
                                        if (r)
                                                return error_fold(r);
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
                                        r = match_rule_link(rule, &peer->bus->sender_matches, monitor);
                                        if (r)
                                                return error_fold(r);
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

                                r = match_rule_link(rule, &name->name_owner_changed_matches, monitor);
                                if (r)
                                        return error_fold(r);
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
                        r = match_rule_link(rule, &peer->bus->sender_matches, monitor);
                        if (r)
                                return error_fold(r);
                }
        } else {
                address_from_string(&addr, rule->keys.sender);
                switch (addr.type) {
                case ADDRESS_TYPE_ID: {
                        sender = peer_registry_find_peer(&peer->bus->peers, addr.id);
                        if (sender) {
                                r = match_rule_link(rule, &sender->sender_matches, monitor);
                                if (r)
                                        return error_fold(r);
                        } else if (addr.id >= peer->bus->peers.ids) {
                                /*
                                 * This peer does not yet exist, by the same
                                 * reasoning as above, keep it as a wildcard
                                 * match.
                                 */
                                r = match_rule_link(rule, &peer->bus->wildcard_matches, monitor);
                                if (r)
                                        return error_fold(r);
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
                        _c_cleanup_(name_unrefp) Name *name = NULL;

                        r = name_registry_ref_name(&peer->bus->names, &name, rule->keys.sender);
                        if (r)
                                return error_fold(r);

                        r = match_rule_link(rule, &name->sender_matches, monitor);
                        if (r)
                                return error_fold(r);
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

        r = peer_link_rule_string(peer, rule_string);
        if (r < 0)
                return error_fold(r);

        r = match_owner_ref_rule(&peer->owned_matches, &rule, peer->user, rule_string, false);
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
        _c_cleanup_(name_unrefp) _c_unused_ Name *name = NULL;
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
        size_t i, n_user_refs;
        int r, poison = 0;

        c_assert(!peer->registered);
        c_assert(!peer->monitor);
        c_assert(c_rbtree_is_empty(&peer->owned_matches.rule_tree));

        /* only fatal errors may occur after this point */
        match_owner_move(&peer->owned_matches, owned_matches);

        c_rbtree_for_each_entry(rule, &peer->owned_matches.rule_tree, owner_node) {
                rule->owner = &peer->owned_matches;
                n_user_refs = rule->n_user_refs;

                /*
                 * Link once for each match instance, in case the user provided
                 * duplicate matches. No need to optimize this; treat it as
                 * individual matches and mirror `peer_add_match()`. We
                 * prefetch the user-refs to guarantee they are constant (in
                 * case `peer_link_match()` would ever want to acquire more
                 * user-refs, for whatever reason).
                 */
                for (i = 0; i < n_user_refs; ++i) {
                        r = peer_link_match(peer, rule, true);
                        if (r && !poison)
                                poison = error_trace(r);
                }
        }

        if (poison)
                /* a fatal error occured, the peer was modified, but still consistent */
                return poison;

        peer->monitor = true;
        ++peer->bus->n_monitors;

        return 0;
}

void peer_stop_monitor(Peer *peer) {
        c_assert(!peer->registered);
        c_assert(peer->monitor);
        c_assert(c_rbtree_is_empty(&peer->owned_matches.rule_tree));

        peer->monitor = false;
        --peer->bus->n_monitors;
}

void peer_flush_matches(Peer *peer) {
        CRBNode *node;

        while ((node = peer->owned_matches.rule_tree.root)) {
                _c_cleanup_(name_unrefp) _c_unused_ Name *name = NULL;
                MatchRule *rule = c_container_of(node, MatchRule, owner_node);

                /*
                 * As above, a match may pin a name.
                 */
                name = peer_match_rule_to_name(rule);

                match_rule_user_unref(rule);
        }
}

static int peer_map_denied_error(int err) {
        switch (err) {
        case POLICY_E_SELINUX_ACCESS_DENIED:
                return BUS_LOG_POLICY_TYPE_SELINUX;
        case POLICY_E_APPARMOR_ACCESS_DENIED:
                return BUS_LOG_POLICY_TYPE_APPARMOR;
        default:
                return BUS_LOG_POLICY_TYPE_INTERNAL;
        }
}

int peer_queue_unicast(PolicySnapshot *sender_policy, NameSet *sender_names, ReplyOwner *sender_replies, User *sender_user, uint64_t sender_id, Peer *receiver, Message *message) {
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
                                          sender_policy->seclabel,
                                          sender_names,
                                          sender_id,
                                          message->metadata.fields.interface,
                                          message->metadata.fields.member,
                                          message->metadata.fields.path,
                                          message->header->type,
                                          false,
                                          message->metadata.fields.unix_fds);
        if (r) {
                if (r == POLICY_E_ACCESS_DENIED ||
                    r == POLICY_E_SELINUX_ACCESS_DENIED ||
                    r == POLICY_E_APPARMOR_ACCESS_DENIED) {
                        log_append_here(receiver->bus->log, LOG_WARNING, 0, NULL);
                        bus_log_append_policy_receive(receiver->bus,
                                                      peer_map_denied_error(r),
                                                      receiver->id, sender_id, sender_names, &receiver_names, message);
                        r = log_commitf(receiver->bus->log, "A security policy denied %s to receive %s %s:%s.%s from :1.%llu.",
                                        message->metadata.fields.destination,
                                        message->header->type == DBUS_MESSAGE_TYPE_METHOD_CALL ? "method call" : "signal",
                                        message->metadata.fields.path, message->metadata.fields.interface, message->metadata.fields.member,
                                        sender_id);
                        if (r)
                                return error_fold(r);

                        return PEER_E_RECEIVE_DENIED;
                }

                return error_fold(r);
        }

        r = policy_snapshot_check_send(sender_policy,
                                       receiver->seclabel,
                                       &receiver_names,
                                       receiver->id,
                                       message->metadata.fields.interface,
                                       message->metadata.fields.member,
                                       message->metadata.fields.path,
                                       message->header->type,
                                       false,
                                       message->metadata.fields.unix_fds);
        if (r) {
                if (r == POLICY_E_ACCESS_DENIED ||
                    r == POLICY_E_SELINUX_ACCESS_DENIED ||
                    r == POLICY_E_APPARMOR_ACCESS_DENIED) {
                        log_append_here(receiver->bus->log, LOG_WARNING, 0, NULL);
                        bus_log_append_policy_send(receiver->bus,
                                                   peer_map_denied_error(r),
                                                   sender_id, receiver->id, sender_names, &receiver_names,
                                                   sender_policy->seclabel, receiver->policy->seclabel, message);
                        r = log_commitf(receiver->bus->log, "A security policy denied :1.%llu to send %s %s:%s.%s to %s.",
                                        sender_id,
                                        message->header->type == DBUS_MESSAGE_TYPE_METHOD_CALL ? "method call" : "signal",
                                        message->metadata.fields.path, message->metadata.fields.interface, message->metadata.fields.member,
                                        message->metadata.fields.destination);
                        if (r)
                                return error_fold(r);

                        return PEER_E_SEND_DENIED;
                }

                return error_fold(r);
        }

        r = connection_queue(&receiver->connection, sender_user, message);
        if (r) {
                if (r == CONNECTION_E_QUOTA)
                        return PEER_E_QUOTA;
                else if (r == CONNECTION_E_UNEXPECTED_FDS)
                        return PEER_E_UNEXPECTED_FDS;

                return error_fold(r);
        }

        slot = NULL;
        return 0;
}

int peer_queue_reply(Peer *sender, const char *destination, uint32_t reply_serial, Message *message) {
        _c_cleanup_(reply_slot_freep) ReplySlot *slot = NULL;
        Peer *receiver = NULL;
        Address addr;
        int r;

        address_from_string(&addr, destination);
        if (addr.type != ADDRESS_TYPE_ID)
                return PEER_E_UNEXPECTED_REPLY;

        slot = reply_slot_get_by_id(&sender->replies, addr.id, reply_serial);
        if (slot)
                receiver = c_container_of(slot->owner, Peer, owned_replies);
        else
                receiver = peer_registry_find_peer(&sender->bus->peers, addr.id);

        if (!receiver)
                return PEER_E_UNEXPECTED_REPLY;

        r = connection_queue(&receiver->connection, NULL, message);
        if (r) {
                if (r == CONNECTION_E_QUOTA || r == CONNECTION_E_UNEXPECTED_FDS) {
                        NameSet sender_names = NAME_SET_INIT_FROM_OWNER(&sender->owned_names);
                        NameSet receiver_names = NAME_SET_INIT_FROM_OWNER(&receiver->owned_names);

                        connection_shutdown(&receiver->connection);

                        log_append_here(receiver->bus->log, LOG_WARNING, 0, DBUS_BROKER_CATALOG_RECEIVE_FAILED);
                        bus_log_append_transaction(receiver->bus, sender->id, receiver->id, &sender_names, &receiver_names,
                                                   sender->policy->seclabel, receiver->policy->seclabel, message);
                        if (r == CONNECTION_E_QUOTA)
                                r = log_commitf(receiver->bus->log, "Peer :1.%llu is being disconnected as it does not have the resources to receive a reply it requested.",
                                                receiver->id);
                        else
                                r = log_commitf(receiver->bus->log, "Peer :1.%llu is being disconnected as it does not support receiving file descriptors it requested.",
                                                receiver->id);

                        if (r)
                                return error_fold(r);
                } else {
                        return error_fold(r);
                }
        }

        return 0;
}

void peer_registry_init(PeerRegistry *registry) {
        *registry = (PeerRegistry)PEER_REGISTRY_INIT;
}

void peer_registry_deinit(PeerRegistry *registry) {
        c_assert(c_rbtree_is_empty(&registry->peer_tree));
        registry->ids = 0;
}

void peer_registry_flush(PeerRegistry *registry) {
        Peer *peer, *safe;
        int r;

        c_rbtree_for_each_entry_safe_postorder_unlink(peer, safe, &registry->peer_tree, registry_node) {
                r = driver_goodbye(peer, true);
                c_assert(!r); /* can not fail in silent mode */
                peer_free(peer);
        }
}

Peer *peer_registry_find_peer(PeerRegistry *registry, uint64_t id) {
        Peer *peer;

        peer = c_rbtree_find_entry(&registry->peer_tree, peer_compare, &id, Peer, registry_node);

        return peer && peer->registered ? peer : NULL;
}

static int peer_deserialize_key_members(char *peer_str, int *fd, uint64_t *id, pid_t *pid,
                                        char **name, char **match_rule, char **sasl) {
        int tmp_str_length[_PEER_INDEX_MAX] = {FD_LENGTH_MAX, ID_LENGTH_MAX, PID_LENGTH_MAX,
                                               UID_LENGTH_MAX, NAME_LENGTH_MAX, LINE_LENGTH_MAX,
                                               SASL_LENGTH_MAX};
        for (int i = 0; i < _PEER_INDEX_MAX; i++) {
                char *tmp_str = malloc(tmp_str_length[i]);
                peer_str = extract_word_inlist(peer_str, &tmp_str);
                if (strlen(tmp_str) <= 0) {
                        return error_origin(-EINVAL);
                }
                switch (i) {
                case PEER_INDEX_FD:
                        *fd = atoi(tmp_str);
                        break;
                case PEER_INDEX_ID:
                        *id = atoi(tmp_str);
                        break;
                case PEER_INDEX_PID:
                        *pid = atoi(tmp_str);
                        break;
                case PEER_INDEX_UID:
                        break;
                case PEER_INDEX_NAME:
                        *name = strndup(tmp_str, NAME_LENGTH_MAX - 1);
                        if (!name)
                                return error_origin(-ENOMEM);
                        break;
                case PEER_INDEX_MATCH_RULE:
                        *match_rule = strndup(tmp_str, LINE_LENGTH_MAX - 1);
                        if (!match_rule)
                                return error_origin(-ENOMEM);
                        break;
                case PEER_INDEX_SASL:
                        *sasl = strndup(tmp_str, SASL_LENGTH_MAX - 1);
                        if (!sasl)
                                return error_origin(-ENOMEM);
                        break;
                default:
                        break;
                }
                if (tmp_str) {
                        free(tmp_str);
                        tmp_str = NULL;
                }
        }
        return 0;
}

static int peer_recover_match_rule(Peer *peer, char *match_rule) {
        char *rule_str = NULL;
        char *match_rule_cur = match_rule;

        while (true) {
                match_rule_cur = extract_list_element(match_rule_cur, &rule_str);
                if (!match_rule_cur)
                        break;
                if (!rule_str)
                        break;
                peer_add_match(peer, rule_str);
                free(rule_str);
                rule_str = NULL;
        }
        if (rule_str) {
                free(rule_str);
                rule_str = NULL;
        }
        return 0;
}

static int peer_recover_sasl(Peer *peer, char *sasl) {
        int sasl_index = SASL_INDEX_SERVER_STATE;
        char *sasl_str = NULL;
        char *sasl_cur = sasl;

        while (sasl_index < _SASL_INDEX_MAX) {
                sasl_cur = extract_list_element(sasl_cur, &sasl_str);
                if (!sasl_cur)
                        break;
                if (!sasl_str)
                        break;
                if (sasl_index == SASL_INDEX_SERVER_STATE)
                        peer->connection.sasl_server.state = atoi(sasl_str);
                else if (sasl_index == SASL_INDEX_SERVER_FDSALLOWED)
                        peer->connection.sasl_server.fds_allowed = atoi(sasl_str);
                else if (sasl_index == SASL_INDEX_CLIENT_STATE)
                        peer->connection.sasl_client.state = atoi(sasl_str);
                sasl_index++;
                free(sasl_str);
                sasl_str = NULL;
        }

        if (sasl_str) {
                free(sasl_str);
                sasl_str = NULL;
        }
        return 0;
}

static int peer_recover_full(ControllerListener *controller_listener, int fd, uint64_t id, pid_t pid,
                             char *name, char *match_rule, char *sasl) {
        Listener *listener = &controller_listener->listener;
        Peer *peer;
        int r;

        /* Recover: fd and id */
        r = peer_new_with_fd(&peer, listener->bus, listener->policy, listener->guid,
                             listener->socket_file.context, fd, id);
        c_list_link_tail(&listener->peer_list, &peer->listener_link);
        r = peer_spawn(peer);
        if (r)
                return error_fold(r);

        /* Recover: sasl */
        peer_recover_sasl(peer, sasl);
        if (r < 0)
                return error_fold(r);

        /* register and mark as recovered */
        peer_register(peer);
        peer->connection.recovered = 1;

        /* Recover: pid */
        peer->pid = pid;

        /* Recover: name */
        NameChange change = NAME_CHANGE_INIT;
        r = name_registry_request_name(&peer->bus->names,
                &peer->owned_names,
                peer->user,
                name,
                0,
                &change);
        if (r != 0 && r != NAME_E_IN_QUEUE)
                return error_fold(r);

        /* Recover: match_rule */
        r = peer_recover_match_rule(peer, match_rule);
        if (r < 0)
                return error_fold(r);
        return 0;
}

char* free_key_member(char *member) {
        if (member) {
                free(member);
        }
        return NULL;
}

int peer_recover_with_fd(int mem_fd, ControllerListener *controller_listener) {
        FILE *f = NULL;
        _c_cleanup_(c_freep) char *buf = malloc(LINE_LENGTH_MAX);
        int r;

        errno = 0;
        f = fdopen(mem_fd, "r");
        if (!f)
                return error_trace(-errno);

        fseek(f, 0, SEEK_SET);
        while (fgets(buf, LINE_LENGTH_MAX, f) != NULL) {
                char *peer_str = string_prefix(buf, "peer=");
                if (!peer_str)
                        continue;

                /* Deserialize key members */
                int fd = 0;
                uint64_t id = 0;
                pid_t pid = 0;
                char *name = NULL, *match_rule = NULL, *sasl = NULL, *pid_path = NULL;
                r = peer_deserialize_key_members(peer_str, &fd, &id, &pid, &name, &match_rule, &sasl);
                if (r < 0) {
                        if (fd > 0)
                                close(fd);
                        name = free_key_member(name);
                        match_rule = free_key_member(match_rule);
                        sasl = free_key_member(sasl);
                        pid_path = free_key_member(pid_path);
                        continue;
                }
                /* If we can't find the pid, skip */
                r = asprintf(&pid_path, "/proc/%"PRIu32, (uint32_t)pid);
                if (r < 0) {
                        if (fd > 0)
                                close(fd);
                        name = free_key_member(name);
                        match_rule = free_key_member(match_rule);
                        sasl = free_key_member(sasl);
                        pid_path = free_key_member(pid_path);
                        continue;
                }
                if (access(pid_path, F_OK) != 0) {
                        if (fd > 0)
                                close(fd);
                        name = free_key_member(name);
                        match_rule = free_key_member(match_rule);
                        sasl = free_key_member(sasl);
                        pid_path = free_key_member(pid_path);
                        continue;
                }

                r = peer_recover_full(controller_listener, fd, id, pid, name, match_rule, sasl);
                if (r < 0) {
                        if (fd > 0)
                                close(fd);
                        name = free_key_member(name);
                        match_rule = free_key_member(match_rule);
                        sasl = free_key_member(sasl);
                        pid_path = free_key_member(pid_path);
                        continue;
                }
                name = free_key_member(name);
                match_rule = free_key_member(match_rule);
                sasl = free_key_member(sasl);
                pid_path = free_key_member(pid_path);
        }
        fclose(f);
        return 0;
}
