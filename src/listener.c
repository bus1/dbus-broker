/*
 * Socket Listener
 */

#include <c-list.h>
#include <c-macro.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include "bus.h"
#include "listener.h"
#include "peer.h"
#include "util/dispatch.h"
#include "util/error.h"

static int listener_dispatch(DispatchFile *file, uint32_t events) {
        Listener *listener = c_container_of(file, Listener, socket_file);
        _c_cleanup_(c_closep) int fd = -1;
        _c_cleanup_(peer_freep) Peer *peer = NULL;
        int r;

        if (!(events & EPOLLIN))
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

        r = peer_new_with_fd(&peer, listener->bus, file->context, fd);
        if (r == PEER_E_QUOTA)
                /*
                 * The user has too many open connections, simply drop this.
                 */
                return 0;
        else if (r)
                return error_fold(r);
        fd = -1; /* consume fd */

        r = peer_spawn(peer);
        if (r)
                return error_fold(r);

        peer = NULL;
        return 0;
}

static int listener_compare(CRBTree *tree, void *k, CRBNode *rb) {
        Listener *listener = c_container_of(rb, Listener, bus_node);
        const char *path = k;

        return strcmp(listener->path, path);
}

/**
 * listener_new_with_fd() - XXX
 */
int listener_new_with_fd(Listener **listenerp, Bus *bus, const char *path, DispatchContext *dispatcher, int socket_fd) {
        _c_cleanup_(listener_freep) Listener *listener = NULL;
        CRBNode **slot, *parent;
        int r;

        slot = c_rbtree_find_slot(&bus->listener_tree, listener_compare, path, &parent);
        if (!slot)
                return LISTENER_E_EXISTS;

        listener = calloc(1, sizeof(*listener) + strlen(path) + 1);
        if (!listener)
                return error_origin(-ENOMEM);

        listener->bus = bus;
        listener->socket_fd = -1;
        listener->socket_file = (DispatchFile)DISPATCH_FILE_NULL(listener->socket_file);
        listener->bus_node = (CRBNode)C_RBNODE_INIT(listener->bus_node);
        listener->peer_list = (CList)C_LIST_INIT(listener->peer_list);
        memcpy((char*)listener->path, path, strlen(path) + 1);

        r = dispatch_file_init(&listener->socket_file,
                               dispatcher,
                               listener_dispatch,
                               socket_fd,
                               EPOLLIN);
        if (r)
                return error_fold(r);

        dispatch_file_select(&listener->socket_file, EPOLLIN);
        c_rbtree_add(&bus->listener_tree, parent, slot, &listener->bus_node);

        listener->socket_fd = socket_fd;
        *listenerp = listener;
        listener = NULL;
        return 0;
}

/**
 * listener_free() - XXX
 */
Listener *listener_free(Listener *listener) {
        if (!listener)
                return NULL;

        assert(c_list_is_empty(&listener->peer_list));

        c_rbtree_remove_init(&listener->bus->listener_tree, &listener->bus_node);
        dispatch_file_deinit(&listener->socket_file);
        listener->socket_fd = c_close(listener->socket_fd);
        free(listener);

        return NULL;
}

Listener *listener_find(Bus *bus, const char *path) {
        return c_rbtree_find_entry(&bus->listener_tree, listener_compare, path, Listener, bus_node);
}
