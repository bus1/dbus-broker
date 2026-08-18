/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: D-Bus Broker Developers */

/*
 * Metrics Listener
 */

#include <c-list.h>
#include <c-rbtree.h>
#include <c-stdaux.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include "bus/bus.h"
#include "bus/metrics.h"
#include "dbus/protocol.h"
#include "util/dispatch.h"
#include "util/error.h"
#include "util/log.h"
#include "util/sampler.h"
#include "util/user.h"

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
                } else {
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

        dispatch_file_select(&client->socket_file, EPOLLHUP | EPOLLOUT);

        *clientp = client;
        client = NULL;
        return 0;
}

/*
 * OpenMetrics label values for the message types we forward. Indexed by the
 * on-the-wire type, so the array must track `_DBUS_MESSAGE_TYPE_N`.
 */
static const char *const metrics_message_types[_DBUS_MESSAGE_TYPE_N] = {
        [DBUS_MESSAGE_TYPE_INVALID] = "invalid",
        [DBUS_MESSAGE_TYPE_METHOD_CALL] = "method_call",
        [DBUS_MESSAGE_TYPE_METHOD_RETURN] = "method_return",
        [DBUS_MESSAGE_TYPE_ERROR] = "error",
        [DBUS_MESSAGE_TYPE_SIGNAL] = "signal",
};

/*
 * `user_slot_to_string()` is meant for human-readable log messages. Metric
 * label values must be stable and lower-case, so keep a separate mapping.
 */
static const char *const metrics_user_slots[_USER_SLOT_N] = {
        [USER_SLOT_BYTES] = "bytes",
        [USER_SLOT_FDS] = "fds",
        [USER_SLOT_MATCHES] = "matches",
        [USER_SLOT_OBJECTS] = "objects",
};

/*
 * Size of a compiled document. The buffer is allocated at this size up front
 * rather than grown: the document is bounded and short-lived, so incremental
 * growth buys nothing but code.
 *
 * This is a backstop against a runaway generator rather than a cardinality
 * policy. A typical system bus emits 10-20K, and this still fits roughly 110
 * users.
 *
 * Note that the emit order is load-bearing. The global counters and gauges are
 * written first and are of fixed size, so they always survive; only the
 * per-user series at the tail are ever dropped. Those are exactly the ones that
 * can grow without bound, and the least useful without the counters anyway.
 *
 * A dropped tail is reported via `dbus_broker_metrics_truncated`, which is
 * always emitted so it can be alerted on without having to special-case an
 * absent series.
 */
#define METRICS_MAX_SIZE (64UL * 1024UL)

#define METRICS_TRAILER_FORMAT \
        "# TYPE dbus_broker_metrics_truncated gauge\n" \
        "# HELP dbus_broker_metrics_truncated Set when the document hit its size limit and series were dropped.\n" \
        "dbus_broker_metrics_truncated %d\n" \
        "# EOF\n"

#define METRICS_TRAILER_SIZE (256UL)

static_assert(sizeof(METRICS_TRAILER_FORMAT) <= METRICS_TRAILER_SIZE,
              "METRICS_TRAILER_SIZE too small for METRICS_TRAILER_FORMAT");

static void metrics_client_vappendf(MetricsClient *client,
                                    size_t limit,
                                    const char *format,
                                    va_list args) {
        size_t n_avail;
        int n;

        if (client->error)
                return;

        n_avail = limit - client->n_buffer;
        n = vsnprintf((char *)client->buffer + client->n_buffer, n_avail, format, args);
        if (n < 0) {
                client->error = error_origin(-EINVAL);
                return;
        }

        if ((size_t)n >= n_avail) {
                client->truncated = true;
                return;
        }

        client->n_buffer += n;
}

static void _c_printf_(2, 3) metrics_client_appendf(MetricsClient *client, const char *format, ...) {
        va_list args;

        if (client->truncated)
                return;

        va_start(args, format);
        metrics_client_vappendf(client, METRICS_MAX_SIZE - METRICS_TRAILER_SIZE, format, args);
        va_end(args);
}

static void _c_printf_(2, 3) metrics_client_appendf_trailer(MetricsClient *client, const char *format, ...) {
        va_list args;

        va_start(args, format);
        metrics_client_vappendf(client, METRICS_MAX_SIZE, format, args);
        va_end(args);
}

static void metrics_compile_counters(MetricsClient *client, Bus *bus) {
        BusMetrics *m = &bus->metrics;
        size_t i;

        metrics_client_appendf(client, "# TYPE dbus_broker_messages counter\n"
                   "# HELP dbus_broker_messages Messages accepted from peers, by message type.\n");
        for (i = 0; i < _DBUS_MESSAGE_TYPE_N; ++i)
                metrics_client_appendf(client, "dbus_broker_messages_total{type=\"%s\"} %"PRIu64"\n",
                        metrics_message_types[i], m->n_dispatched[i]);

        metrics_client_appendf(client, "# TYPE dbus_broker_message_bytes counter\n"
                   "# UNIT dbus_broker_message_bytes bytes\n"
                   "# HELP dbus_broker_message_bytes Wire bytes accepted from peers.\n"
                   "dbus_broker_message_bytes_total %"PRIu64"\n",
                m->n_dispatched_bytes);

        metrics_client_appendf(client, "# TYPE dbus_broker_broadcast_deliveries counter\n"
                   "# HELP dbus_broker_broadcast_deliveries Signal copies queued to subscribers. "
                   "Divided by the signal message count this is the broadcast fan-out factor.\n"
                   "dbus_broker_broadcast_deliveries_total %"PRIu64"\n",
                m->n_broadcast_deliveries);

        metrics_client_appendf(client, "# TYPE dbus_broker_quota_exceeded counter\n"
                   "# HELP dbus_broker_quota_exceeded Resource charges refused for exceeding a user quota.\n");
        for (i = 0; i < bus->users.n_slots && i < _USER_SLOT_N; ++i)
                metrics_client_appendf(client, "dbus_broker_quota_exceeded_total{slot=\"%s\"} %"PRIu64"\n",
                        metrics_user_slots[i], bus->users.n_quota_exceeded[i]);

        metrics_client_appendf(client, "# TYPE dbus_broker_quota_disconnects counter\n"
                   "# HELP dbus_broker_quota_disconnects Peers disconnected for failing to drain their socket.\n");
        for (i = 0; i < _BUS_QUOTA_DISCONNECT_N; ++i)
                metrics_client_appendf(client, "dbus_broker_quota_disconnects_total{reason=\"%s\"} %"PRIu64"\n",
                        bus_quota_disconnect_to_string(i), m->n_quota_disconnects[i]);

        metrics_client_appendf(client, "# TYPE dbus_broker_connections_refused counter\n"
                   "# HELP dbus_broker_connections_refused Connections rejected because the user is out of quota. "
                   "A non-zero rate means the bus is closed for that UID.\n"
                   "dbus_broker_connections_refused_total %"PRIu64"\n",
                m->n_connections_refused);
}

static void metrics_compile_gauges(MetricsClient *client, Bus *bus) {
        Sampler *sampler = &bus->sampler;

        metrics_client_appendf(client, "# TYPE dbus_broker_peers gauge\n"
                   "# HELP dbus_broker_peers Connected peers, by registration state.\n"
                   "dbus_broker_peers{state=\"registered\"} %zu\n"
                   "dbus_broker_peers{state=\"incomplete\"} %zu\n",
                bus->peers.n_registered,
                bus->peers.n_peers - bus->peers.n_registered);

        metrics_client_appendf(client, "# TYPE dbus_broker_names gauge\n"
                   "# HELP dbus_broker_names Well-known names with a primary owner.\n"
                   "dbus_broker_names %zu\n",
                bus->names.n_primaries);

        metrics_client_appendf(client, "# TYPE dbus_broker_match_rules gauge\n"
                   "# HELP dbus_broker_match_rules Installed match rules.\n"
                   "dbus_broker_match_rules %zu\n",
                bus->match_counters.n_subscriptions);

        metrics_client_appendf(client, "# TYPE dbus_broker_monitors gauge\n"
                   "# HELP dbus_broker_monitors Peers that called BecomeMonitor.\n"
                   "dbus_broker_monitors %"PRIu64"\n",
                bus->n_monitors);

        metrics_client_appendf(client, "# TYPE dbus_broker_dispatch_max_seconds gauge\n"
                   "# UNIT dbus_broker_dispatch_max_seconds seconds\n"
                   "# HELP dbus_broker_dispatch_max_seconds Slowest single message dispatch observed.\n"
                   "dbus_broker_dispatch_max_seconds %.9f\n",
                sampler->count ? (double)sampler->maximum / 1000000000.0 : 0.0);
}

static void metrics_compile_users(MetricsClient *client, Bus *bus) {
        User *user;
        size_t i;

        metrics_client_appendf(client, "# TYPE dbus_broker_user_quota_used gauge\n"
                   "# HELP dbus_broker_user_quota_used Resources in use by a UID, by quota slot.\n");
        c_rbtree_for_each_entry(user, &bus->users.user_tree, registry_node)
                for (i = 0; i < bus->users.n_slots && i < _USER_SLOT_N; ++i)
                        metrics_client_appendf(client, "dbus_broker_user_quota_used{uid=\"%"PRIu32"\",slot=\"%s\"} %u\n",
                                (uint32_t)user->uid,
                                metrics_user_slots[i],
                                user->slots[i].max - user->slots[i].n);

        metrics_client_appendf(client, "# TYPE dbus_broker_user_quota_max gauge\n"
                   "# HELP dbus_broker_user_quota_max Resource limit of a UID, by quota slot.\n");
        c_rbtree_for_each_entry(user, &bus->users.user_tree, registry_node)
                for (i = 0; i < bus->users.n_slots && i < _USER_SLOT_N; ++i)
                        metrics_client_appendf(client, "dbus_broker_user_quota_max{uid=\"%"PRIu32"\",slot=\"%s\"} %u\n",
                                (uint32_t)user->uid,
                                metrics_user_slots[i],
                                user->slots[i].max);

        metrics_client_appendf(client, "# TYPE dbus_broker_user_actors gauge\n"
                   "# HELP dbus_broker_user_actors Distinct UIDs currently charging resources to this UID.\n");
        c_rbtree_for_each_entry(user, &bus->users.user_tree, registry_node)
                metrics_client_appendf(client, "dbus_broker_user_actors{uid=\"%"PRIu32"\"} %u\n",
                        (uint32_t)user->uid, user->n_usages);
}

static int metrics_compile(MetricsClient *client, Bus *bus) {
        int r;

        c_assert(!client->buffer);

        client->buffer = malloc(METRICS_MAX_SIZE);
        if (!client->buffer)
                return error_origin(-ENOMEM);

        /*
         * Careful: this runs synchronously on the dispatch loop, so everything
         * emitted here must be cheap. In particular, do not add anything that
         * walks the name registry per peer.
         */
        metrics_compile_counters(client, bus);
        metrics_compile_gauges(client, bus);
        metrics_compile_users(client, bus);

        metrics_client_appendf_trailer(client, METRICS_TRAILER_FORMAT, client->truncated ? 1 : 0);

        if (client->error)
                return error_trace(client->error);

        if (client->truncated) {
                log_append_here(bus->log, LOG_WARNING, 0, NULL);
                r = log_commitf(bus->log,
                                "Metrics document truncated at %zu bytes; per-user series were dropped.",
                                client->n_buffer);
                if (r)
                        return error_fold(r);
        }

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

        r = metrics_compile(client, metrics->bus);
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
