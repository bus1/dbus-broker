/*
 * Metrics Listener
 */

#include <c-list.h>
#include <c-stdaux.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include "bus/bus.h"
#include "bus/metrics.h"
#include "util/dispatch.h"
#include "util/error.h"

static MetricsClient *metrics_client_free(MetricsClient *client) {
        if (!client)
                return NULL;

        free(client->buffer);
        dispatch_file_deinit(&client->socket_file);
        c_close(client->socket_fd);
        c_list_unlink(&client->metrics_link);
        free(client);

        return NULL;
}

C_DEFINE_CLEANUP(MetricsClient *, metrics_client_free);

static int metrics_client_dispatch(DispatchFile *file) {
        MetricsClient *client = c_container_of(file, MetricsClient, socket_file);
        _c_cleanup_(c_closep) int fd = -1;
        uint32_t events = dispatch_file_events(file);
        bool hup = false;

        if (events & EPOLLHUP) {
                hup = true;
        } else if (events & EPOLLOUT) {
                ssize_t len;

                len = send(
                        client->socket_fd,
                        client->buffer + client->i_buffer,
                        client->n_buffer - client->i_buffer,
                        MSG_DONTWAIT | MSG_NOSIGNAL
                );
                if (len < 0) {
                        switch (errno) {
                        case EAGAIN:
                                dispatch_file_clear(file, EPOLLOUT);
                                break;
                        case ECOMM:
                        case ECONNABORTED:
                        case ECONNRESET:
                        case EHOSTDOWN:
                        case EHOSTUNREACH:
                        case EIO:
                        case ENOBUFS:
                        case ENOMEM:
                        case EPIPE:
                        case EPROTO:
                        case EREMOTEIO:
                        case ESHUTDOWN:
                        case ETIMEDOUT:
                                hup = true;
                                break;
                        default:
                                return error_origin(-errno);
                        }
                } else if (len >= 0) {
                        client->i_buffer += len;
                        if (client->i_buffer >= client->n_buffer)
                                hup = true;
                        else
                                dispatch_file_clear(file, EPOLLOUT);
                }
        }


        if (hup)
                metrics_client_free(client);

        return 0;
}

static int metrics_client_new_with_fd(MetricsClient **clientp, Metrics *metrics, int fd) {
        _c_cleanup_(metrics_client_freep) MetricsClient *client = NULL;
        int r;

        client = calloc(1, sizeof(*client));
        if (!client)
                return error_origin(-ENOMEM);

        c_list_link_tail(&metrics->client_list, &client->metrics_link);
        client->socket_fd = -1;

        r = dispatch_file_init(
                &client->socket_file,
                metrics->socket_file.context,
                metrics_client_dispatch,
                fd,
                EPOLLHUP | EPOLLOUT,
                EPOLLOUT
        );
        if (r)
                return error_fold(r);

        client->socket_fd = fd;
        dispatch_file_select(&metrics->socket_file, EPOLLHUP | EPOLLOUT);

        *clientp = client;
        client = NULL;
        return 0;
}

static int metrics_compile(MetricsClient *client) {
        int r;

        c_assert(!client->buffer);

        r = asprintf(
                (void *)&client->buffer,
                "# EOF"
        );
        if (r < 0)
                return error_origin(-errno);

        return 0;
}

static int metrics_dispatch(DispatchFile *file) {
        Metrics *metrics = c_container_of(file, Metrics, socket_file);
        _c_cleanup_(c_closep) int fd = -1;
        MetricsClient *client;
        int r;

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

        r = metrics_client_new_with_fd(&client, metrics, fd);
        if (r)
                return error_fold(r);
        fd = -1; /* consumed by client */

        r = metrics_compile(client);
        if (r)
                return error_fold(r);

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
        MetricsClient *client;

        while ((client = c_list_first_entry(&metrics->client_list, MetricsClient, metrics_link)))
                metrics_client_free(client);

        dispatch_file_deinit(&metrics->socket_file);
        metrics->socket_fd = c_close(metrics->socket_fd);
        metrics->bus = NULL;
}
