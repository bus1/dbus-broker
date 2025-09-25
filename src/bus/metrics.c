/*
 * Metrics Listener
 */

#include <c-stdaux.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include "bus/bus.h"
#include "bus/metrics.h"
#include "util/dispatch.h"
#include "util/error.h"

static int metrics_dispatch(DispatchFile *file) {
        Metrics *metrics = c_container_of(file, Metrics, socket_file);
        _c_cleanup_(peer_freep) Peer *peer = NULL;
        _c_cleanup_(c_closep) int fd = -1;

        if (!(dispatch_file_events(file) & EPOLLIN))
                return 0;

        fd = accept4(metrics->socket_fd, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
        if (fd < 0) {
                if (errno == EAGAIN) {
                        /*
                         * EAGAIN implies there are no pending incoming
                         * connections. Catch this, clear EPOLLIN and tell the
                         * caller about it.
                         */
                        dispatch_file_clear(&metrics->socket_file, EPOLLIN);
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

        /* FIXME: Dump metrics on the client. */

        return 0;
}

/**
 * metrics_init_with_fd() - XXX
 */
int metrics_init_with_fd(Metrics *m,
                         Bus *bus,
                         DispatchContext *dispatcher,
                         int socket_fd) {
        _c_cleanup_(metrics_deinitp) Metrics *metrics = m;
        int r;

        *metrics = (Metrics)METRICS_NULL(*metrics);
        metrics->bus = bus;

        r = dispatch_file_init(&metrics->socket_file,
                               dispatcher,
                               metrics_dispatch,
                               socket_fd,
                               EPOLLIN,
                               EPOLLIN);
        if (r)
                return error_fold(r);

        dispatch_file_select(&metrics->socket_file, EPOLLIN);

        metrics->socket_fd = socket_fd;
        metrics = NULL;
        return 0;
}

/**
 * metrics_deinit() - XXX
 */
void metrics_deinit(Metrics *metrics) {
        dispatch_file_deinit(&metrics->socket_file);
        metrics->socket_fd = c_close(metrics->socket_fd);
        metrics->bus = NULL;
}
