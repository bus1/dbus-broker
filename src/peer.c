/*
 * Peers
 */

#include <c-macro.h>
#include <poll.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include "bus.h"
#include "dbus-message.h"
#include "dbus-socket.h"
#include "dispatch.h"
#include "peer.h"
#include "user.h"

static int peer_dispatch_read_message(Peer *peer) {
        _c_cleanup_(dbus_message_unrefp) DBusMessage *message = NULL;
        int r;

        r = dbus_socket_read_message(peer->socket, &message);
        if (r < 0)
                return r;

        return 0;
}

static int peer_dispatch_read_line(Peer *peer) {
        char *line_in, *line_out;
        size_t *pos, n_line;
        int r;

        r = dbus_socket_read_line(peer->socket, &line_in, &n_line);
        if (r < 0)
                return r;

        r = dbus_socket_reserve_line(peer->socket,
                                     DBUS_SASL_MAX_OUT_LINE_LENGTH,
                                     &line_out,
                                     &pos);
        if (r < 0)
                return r;

        r = dbus_sasl_dispatch(&peer->sasl, line_in, line_out, pos);
        if (r < 0) {
                return r;
        } else if (r == 1) {
                peer->authenticated = true;
                return 0;
        }

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
                        dispatch_file_clear(&peer->dispatch_file, POLLIN);
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

        r = dbus_socket_write(peer->socket);
        if (r == -EAGAIN) {
                /* not able to write more */
                dispatch_file_clear(&peer->dispatch_file, POLLOUT);
                return 0;
        } if (r < 0) {
                /* XXX: swallow error code and tear down this peer */
                return 0;
        }

        return 0;
}

int peer_dispatch(DispatchFile *file, uint32_t mask) {
        Peer *peer = c_container_of(file, Peer, dispatch_file);
        int r;

        if (mask & POLLIN) {
                r = peer_dispatch_read(peer);
                if (r < 0)
                        return r;
        }

        if (mask & POLLOUT) {
                r = peer_dispatch_write(peer);
                if (r < 0)
                        return r;
        }

        return 0;
}

/**
 * peer_new() - XXX
 */
int peer_new(Bus *bus, Peer **peerp, int fd, uid_t uid, pid_t pid) {
        _c_cleanup_(peer_freep) Peer *peer = NULL;
        _c_cleanup_(user_entry_unrefp) UserEntry *user = NULL;
        int r;

        r = user_entry_ref_by_uid(bus->users, &user, uid);
        if (r < 0)
                return r;

        if (user->n_peers < 1)
                return -EDQUOT;

        peer = calloc(1, sizeof(*peer));
        if (!peer)
                return -ENOMEM;

        user->n_peers --;

        c_rbnode_init(&peer->rb);
        peer->user = user;
        peer->pid = pid;
        user = NULL;
        dispatch_file_init(&peer->dispatch_file,
                           peer_dispatch,
                           bus->dispatcher,
                           &bus->ready_list);
        dbus_sasl_init(&peer->sasl, uid, bus->guid);

        r = dbus_socket_new(&peer->socket, fd);
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
        if (!peer)
                return NULL;

        assert(!peer->names.root);
        assert(!c_rbnode_is_linked(&peer->rb));

        peer->user->n_peers ++;

        dispatch_file_deinit(&peer->dispatch_file);
        dbus_sasl_deinit(&peer->sasl);
        dbus_socket_free(peer->socket);
        user_entry_unref(peer->user);
        free(peer);

        return NULL;
}

int peer_start(Peer *peer) {
        return dispatch_file_select(&peer->dispatch_file,
                                    peer->socket->fd,
                                    POLLIN | POLLOUT);
}

void peer_stop(Peer *peer) {
        dispatch_file_drop(&peer->dispatch_file);
}
