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
#include "user.h"
#include "util/dispatch.h"
#include "util/error.h"
#include "util/fdlist.h"
#include "util/metrics.h"

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
                if (r == CONNECTION_E_EOF) {
                        driver_matches_cleanup(&peer->owned_matches, peer->bus, peer->user);
                        r = driver_goodbye(peer, false);
                        if (r)
                                return error_fold(r);
                        connection_shutdown(&peer->connection);
                        break;
                } else if (r == CONNECTION_E_RESET) {
                        driver_matches_cleanup(&peer->owned_matches, peer->bus, peer->user);
                        r = driver_goodbye(peer, false);
                        if (r)
                                return error_fold(r);
                        connection_close(&peer->connection);
                        peer_free(peer);
                        return 0;
                } else if (r)
                        return error_fold(r);
                if (!m)
                        break;

                metrics_sample_start(&peer->metrics);
                r = driver_dispatch(peer, m);
                metrics_sample_end(&peer->metrics);
                if (r == DRIVER_E_DISCONNECT) {
                        driver_matches_cleanup(&peer->owned_matches, peer->bus, peer->user);
                        r = driver_goodbye(peer, false);
                        if (r)
                                return error_fold(r);
                        connection_close(&peer->connection);
                        peer_free(peer);
                        return 0;
                } else if (r)
                        return error_fold(r);
        }

        if (dispatch_file_is_ready(file, EPOLLOUT)) {
                r = connection_dispatch(&peer->connection, EPOLLOUT);
                if (r)
                        return error_fold(r);
        }

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

        r = user_registry_ref_user(&bus->users, &user, ucred.uid);
        if (r < 0)
                return error_fold(r);

        if (user->n_peers < 1)
                return PEER_E_QUOTA;

        r = peer_get_peersec(fd, &seclabel, &n_seclabel);
        if (r < 0)
                return error_trace(r);

        peer = calloc(1, sizeof(*peer));
        if (!peer)
                return error_origin(-ENOMEM);

        user->n_peers --;

        peer->bus = bus;
        peer->connection = (Connection)CONNECTION_NULL(peer->connection);
        c_rbnode_init(&peer->registry_node);
        peer->user = user;
        user = NULL;
        peer->pid = ucred.pid;
        peer->seclabel = seclabel;
        seclabel = NULL;
        peer->n_seclabel = n_seclabel;
        peer->metrics = (Metrics)METRICS_INIT;
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

        peer->user->n_peers ++;

        c_rbtree_remove_init(&peer->bus->peers.peer_tree, &peer->registry_node);

        fd = peer->connection.socket.fd;

        reply_owner_deinit(&peer->owned_replies);
        reply_registry_deinit(&peer->replies_outgoing);
        match_owner_deinit(&peer->owned_matches);
        match_registry_deinit(&peer->matches);
        name_owner_deinit(&peer->owned_names);
        metrics_deinit(&peer->metrics);
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

        peer->registered = true;
}

void peer_unregister(Peer *peer) {
        assert(peer->registered);

        peer->registered = false;
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
        CRBNode *node;
        int r;

        while ((node = registry->peer_tree.root)) {
                Peer *peer = c_container_of(node, Peer, registry_node);

                driver_matches_cleanup(&peer->owned_matches, peer->bus, peer->user);
                r = driver_goodbye(peer, true);
                assert(!r); /* can not fail in silent mode */
                connection_close(&peer->connection);
                peer_free(peer);
        }
}

Peer *peer_registry_find_peer(PeerRegistry *registry, uint64_t id) {
        Peer *peer;

        peer = c_rbtree_find_entry(&registry->peer_tree, peer_compare, &id, Peer, registry_node);

        return peer->registered ? peer : NULL;
}
