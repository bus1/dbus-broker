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
#include "dbus-match.h"
#include "dispatch.h"
#include "driver.h"
#include "message.h"
#include "peer.h"
#include "socket.h"
#include "user.h"

static int peer_dispatch_read_message(Peer *peer) {
        _c_cleanup_(message_unrefp) Message *message = NULL;
        int r;

        r = socket_read_message(peer->socket, &message);
        if (r < 0)
                return r;

        r = driver_handle_message(peer, message);
        if (r < 0)
                return r;

        return 0;
}

static int peer_dispatch_read_line(Peer *peer) {
        char *line_in, *line_out;
        size_t *pos, n_line;
        int r;

        r = socket_read_line(peer->socket, &line_in, &n_line);
        if (r < 0)
                return r;

        r = socket_queue_line(peer->socket,
                              DBUS_SASL_MAX_OUT_LINE_LENGTH,
                              &line_out,
                              &pos);
        if (r < 0)
                return r;

        r = dbus_sasl_dispatch(&peer->sasl, line_in, line_out, pos);
        if (r < 0)
                return r;
        else if (r == 0)
                dispatch_file_select(&peer->dispatch_file, EPOLLOUT);
        else
                peer->authenticated = true;

        return 0;
}

static int peer_dispatch_read(Peer *peer) {
        int r;

        for (unsigned int i = 0; i < 32; i ++) {
                if (_c_likely_(peer->authenticated)) {
                        r = peer_dispatch_read_message(peer);
                } else {
                        r = peer_dispatch_read_line(peer);
                }
                if (r == -EAGAIN) {
                        /* nothing to be done */
                        dispatch_file_clear(&peer->dispatch_file, EPOLLIN);
                        return 0;
                } else if (r < 0) {
                        /* XXX: swallow error code and tear down this peer */
                        return 0;
                }
        }

        return 0;
}

static int peer_dispatch_write(Peer *peer) {
        int r;

        r = socket_write(peer->socket);
        if (r == -EAGAIN) {
                /* not able to write more */
                dispatch_file_clear(&peer->dispatch_file, EPOLLOUT);
                return 0;
        } else if (r == 0) {
                /* nothing more to write */
                dispatch_file_deselect(&peer->dispatch_file, EPOLLOUT);
        } else if (r < 0) {
                /* XXX: swallow error code and tear down this peer */
                return 0;
        }

        return 0;
}

int peer_dispatch(DispatchFile *file, uint32_t mask) {
        Peer *peer = c_container_of(file, Peer, dispatch_file);
        int r;

        if (mask & EPOLLIN) {
                r = peer_dispatch_read(peer);
                if (r < 0)
                        return r;
        }

        if (mask & EPOLLOUT) {
                r = peer_dispatch_write(peer);
                if (r < 0)
                        return r;
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
                return -ENOMEM;

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
                        return -ENOMEM;

                label = l;
        }

        return 0;
}

/**
 * peer_new() - XXX
 */
int peer_new(Peer **peerp,
             Bus *bus,
             int fd) {
        _c_cleanup_(peer_freep) Peer *peer = NULL;
        _c_cleanup_(user_entry_unrefp) UserEntry *user = NULL;
        _c_cleanup_(c_freep) char *seclabel = NULL;
        size_t n_seclabel;
        struct ucred ucred;
        socklen_t socklen = sizeof(ucred);
        int r;

        r = getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &ucred, &socklen);
        if (r < 0)
                return -errno;

        r = user_registry_ref_entry(&bus->users, &user, ucred.uid);
        if (r < 0)
                return r;

        if (user->n_peers < 1)
                return -EDQUOT;

        r = peer_get_peersec(fd, &seclabel, &n_seclabel);
        if (r < 0)
                return r;

        peer = calloc(1, sizeof(*peer));
        if (!peer)
                return -ENOMEM;

        user->n_peers --;

        peer->bus = bus;
        c_rbnode_init(&peer->rb);
        peer->user = user;
        user = NULL;
        peer->pid = ucred.pid;
        peer->seclabel = seclabel;
        seclabel = NULL;
        peer->n_seclabel = n_seclabel;
        peer->dispatch_file = (DispatchFile)DISPATCH_FILE_NULL(peer->dispatch_file);
        dbus_sasl_init(&peer->sasl, ucred.uid, bus->guid);

        r = socket_new(&peer->socket, fd);
        if (r < 0)
                return r;

        r = dispatch_file_init(&peer->dispatch_file,
                               &bus->dispatcher,
                               &bus->ready_list,
                               peer_dispatch,
                               fd,
                               EPOLLIN | EPOLLOUT);
        if (r < 0)
                return r;

        peer->id = bus->ids ++;

        *peerp = peer;
        peer = NULL;
        return 0;
}

/**
 * peer_free() - XXX
 */
Peer *peer_free(Peer *peer) {
        CRBNode *node, *next;

        if (!peer)
                return NULL;

        assert(!peer->names.root);
        assert(!c_rbnode_is_linked(&peer->rb));

        peer->user->n_peers ++;

        for (node = c_rbtree_first_postorder(&peer->match_rules),
             next = c_rbnode_next_postorder(node);
             node;
             node = next, next = c_rbnode_next_postorder(node)) {
                DBusMatchRule *rule = c_container_of(node,
                                                     DBusMatchRule,
                                                     rb_peer);

                dbus_match_rule_free(&rule->n_refs, NULL);
        }

        dispatch_file_deinit(&peer->dispatch_file);
        dbus_sasl_deinit(&peer->sasl);
        socket_free(peer->socket);
        user_entry_unref(peer->user);
        free(peer->seclabel);
        free(peer);

        return NULL;
}

void peer_start(Peer *peer) {
        return dispatch_file_select(&peer->dispatch_file, EPOLLIN);
}

void peer_stop(Peer *peer) {
        return dispatch_file_deselect(&peer->dispatch_file, EPOLLIN);
}
