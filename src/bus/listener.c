/*
 * Socket Listener
 */

#include <c-list.h>
#include <c-stdaux.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include "bus/bus.h"
#include "bus/listener.h"
#include "bus/peer.h"
#include "bus/policy.h"
#include "util/dispatch.h"
#include "util/error.h"

static int listener_dispatch(DispatchFile *file) {
        Listener *listener = c_container_of(file, Listener, socket_file);
        _c_cleanup_(peer_freep) Peer *peer = NULL;
        _c_cleanup_(c_closep) int fd = -1;
        int r;

        if (!(dispatch_file_events(file) & EPOLLIN))
                return 0;

        fd = accept4(listener->socket_fd, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
        if (fd < 0) {
                if (errno == EAGAIN) {
                        /*
                         * EAGAIN implies there are no pending incoming
                         * connections. Catch this, clear EPOLLIN and tell the
                         * caller about it.
                         */
                        dispatch_file_clear(&listener->socket_file, EPOLLIN);
                        return 0;
                } else {
                        /*
                         * The linux UDS layer does not return pending errors
                         * on the child socket (unlike the TCP layer). Hence,
                         * there are no known errors to check for.
                         */
                        return error_origin(-errno);
                }
        }

        r = peer_new_with_fd(&peer, listener->bus, listener->policy, listener->guid, file->context, fd);
        if (r == PEER_E_QUOTA || r == PEER_E_CONNECTION_REFUSED)
                /*
                 * The user has too many open connections, or a policy disallows it to
                 * connect. Simply drop this.
                 */
                return 0;
        else if (r)
                return error_fold(r);
        fd = -1; /* consume fd */

        c_list_link_tail(&listener->peer_list, &peer->listener_link);

        r = peer_spawn(peer);
        if (r)
                return error_fold(r);

        r = peer_dispatch(&peer->connection.socket_file);
        peer = NULL;
        return error_fold(r);
}

/**
 * listener_init_with_fd() - XXX
 */
int listener_init_with_fd(Listener *l,
                          Bus *bus,
                          DispatchContext *dispatcher,
                          int socket_fd,
                          PolicyRegistry *policy) {
        _c_cleanup_(listener_deinitp) Listener *listener = l;
        int r;

        *listener = (Listener)LISTENER_NULL(*listener);
        listener->bus = bus;

        /*
         * Every listener socket needs its own, unique UUID for clients to
         * identify it. We simply generate those UUIDs from the bus-uuid, by
         * XOR'ing a unique 64bit counter on the lower 64bit, leaving the upper
         * 64bit unchanged.
         */
        ++bus->listener_ids;
        for (size_t i = 0; i < sizeof(listener->guid); ++i) {
                listener->guid[i] = bus->guid[i];
                if (i < sizeof(uint64_t))
                        listener->guid[i] ^= (bus->listener_ids >> (8 * i)) & 0xff;
        }

        r = dispatch_file_init(&listener->socket_file,
                               dispatcher,
                               listener_dispatch,
                               socket_fd,
                               EPOLLIN,
                               EPOLLIN);
        if (r)
                return error_fold(r);

        dispatch_file_select(&listener->socket_file, EPOLLIN);

        listener->socket_fd = socket_fd;
        listener->policy = policy;
        listener = NULL;
        return 0;
}

/**
 * listener_deinit() - XXX
 */
void listener_deinit(Listener *listener) {
        c_assert(c_list_is_empty(&listener->peer_list));

        policy_registry_free(listener->policy);
        dispatch_file_deinit(&listener->socket_file);
        listener->socket_fd = c_close(listener->socket_fd);
        listener->bus = NULL;
}

/**
 * listener_set_policy() - XXX
 */
int listener_set_policy(Listener *listener, PolicyRegistry *registry) {
        Peer *peer;
        int r;

        c_list_for_each_entry(peer, &listener->peer_list, listener_link) {
                PolicySnapshot *policy;

                r = policy_snapshot_new(&policy, registry, peer->seclabel, peer->user->uid, peer->gids, peer->n_gids);
                if (r)
                        return error_fold(r);

                policy_snapshot_free(peer->policy);
                peer->policy = policy;
        }

        policy_registry_free(listener->policy);
        listener->policy = registry;
        return 0;
}
