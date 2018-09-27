/*
 * Connection
 */

#include <c-macro.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include "dbus/connection.h"
#include "dbus/message.h"
#include "dbus/socket.h"
#include "util/dispatch.h"
#include "util/error.h"
#include "util/user.h"

static int connection_init(Connection *c,
                           DispatchContext *dispatch_ctx,
                           DispatchFn dispatch_fn,
                           User *user,
                           int fd) {
        _c_cleanup_(connection_deinitp) Connection *connection = c;
        int r;

        *connection = (Connection)CONNECTION_NULL(*connection);
        socket_init(&connection->socket, user, fd);

        r = dispatch_file_init(&connection->socket_file,
                               dispatch_ctx,
                               dispatch_fn,
                               fd,
                               EPOLLHUP | EPOLLIN | EPOLLOUT,
                               EPOLLIN | EPOLLOUT);
        if (r)
                return error_fold(r);

        connection = NULL;
        return 0;
}

/**
 * connection_init_server() - XXX
 */
int connection_init_server(Connection *c,
                           DispatchContext *dispatch_ctx,
                           DispatchFn dispatch_fn,
                           User *user,
                           const char *guid,
                           int fd) {
        int r;

        r = connection_init(c,
                            dispatch_ctx,
                            dispatch_fn,
                            user,
                            fd);
        if (r)
                return error_trace(r);

        c->server = true;
        sasl_server_init(&c->sasl_server, user->uid, guid);
        return 0;
}

/**
 * connection_init_client() - XXX
 */
int connection_init_client(Connection *c,
                           DispatchContext *dispatch_ctx,
                           DispatchFn dispatch_fn,
                           User *user,
                           int fd) {
        int r;

        r = connection_init(c,
                            dispatch_ctx,
                            dispatch_fn,
                            user,
                            fd);
        if (r)
                return error_trace(r);

        c->server = false;
        sasl_client_init(&c->sasl_client);
        return 0;
}

/**
 * connection_deinit() - XXX
 */
void connection_deinit(Connection *connection) {
        sasl_client_deinit(&connection->sasl_client);
        sasl_server_deinit(&connection->sasl_server);
        dispatch_file_deinit(&connection->socket_file);
        socket_deinit(&connection->socket);
}

static int connection_feed_sasl(Connection *connection, const char *input, size_t n_input) {
        const char *output;
        size_t n_output;
        int r;

        /* client SASL allows NULL input as bootstrap */
        assert(!connection->server || input);
        assert(!connection->authenticated);

        if (connection->server)
                r = sasl_server_dispatch(&connection->sasl_server, input, n_input, &output, &n_output);
        else
                r = sasl_client_dispatch(&connection->sasl_client, input, n_input, &output, &n_output);

        if (r > 0) {
                connection_close(connection);
                return CONNECTION_E_EOF;
        } else if (r < 0) {
                return error_fold(r);
        }

        connection->authenticated = connection->server ?
                                    sasl_server_is_done(&connection->sasl_server) :
                                    sasl_client_is_done(&connection->sasl_client);

        /*
         * If the SASL exchange triggered an outgoing message, we will queue it
         * on the socket. There're 3 things that might fail:
         *
         *     1) The socket was already closed for output. In that case we
         *        black-hole the message. The trigger of the write-side
         *        shutdown must have already taken care of everything else.
         *
         *     2) The message exceeds the connection quota. Since this is a
         *        self-triggered message, the connection itself is responsible
         *        and thus at fault. We simply close the write-side of the
         *        connection and wait for them to react to it.
         *
         *     3) A fatal error. Just like always, we simply fold it.
         */
        if (output) {
                r = socket_queue_line(&connection->socket, NULL, output, n_output);
                if (!r)
                        dispatch_file_select(&connection->socket_file, EPOLLOUT);
                else if (r == SOCKET_E_QUOTA)
                        connection_shutdown(connection);
                else if (r != SOCKET_E_SHUTDOWN)
                        return error_fold(r);
        }

        return 0;
}

/**
 * connection_open() - XXX
 */
int connection_open(Connection *connection) {
        int r;

        assert(socket_is_running(&connection->socket));

        if (!connection->server) {
                /* bootstrap client SASL */
                r = connection_feed_sasl(connection, NULL, 0);
                if (r)
                        return error_trace(r);
        }

        dispatch_file_select(&connection->socket_file, EPOLLHUP | EPOLLIN);
        return 0;
}

/**
 * connection_shutdown() - XXX
 */
void connection_shutdown(Connection *connection) {
        /*
         * A connection shutdown stops the write-side channel. If that happens
         * after the read-side was already torn down, we must re-select
         * EPOLLHUP so the main-loop of @connection gets woken up again. We
         * know that EPOLLHUP must be signalled, since it is implied by the
         * combination (hup_in && hup_out).
         */
        socket_shutdown(&connection->socket);
        if (!socket_is_running(&connection->socket))
                dispatch_file_select(&connection->socket_file, EPOLLHUP);
}

/**
 * connection_close() - XXX
 */
void connection_close(Connection *connection) {
        socket_close(&connection->socket);
}

/**
 * connection_dispatch() - XXX
 */
int connection_dispatch(Connection *connection, uint32_t events) {
        static const uint32_t interest[] = { EPOLLIN, EPOLLHUP, EPOLLOUT };
        size_t i;
        int r;

        for (i = 0; i < C_ARRAY_SIZE(interest); ++i) {
                if (events & interest[i]) {
                        r = socket_dispatch(&connection->socket, interest[i]);
                        if (!r)
                                dispatch_file_clear(&connection->socket_file, interest[i]);
                        else if (r == SOCKET_E_LOST_INTEREST)
                                dispatch_file_deselect(&connection->socket_file, interest[i]);
                        else if (r != SOCKET_E_PREEMPTED)
                                return error_fold(r);
                }
        }

        return 0;
}

/**
 * connection_dequeue() - XXX
 */
int connection_dequeue(Connection *connection, Message **messagep) {
        const char *input;
        size_t n_input;
        int r;

        if (_c_unlikely_(!connection->authenticated)) {
                do {
                        r = socket_dequeue_line(&connection->socket, &input, &n_input);
                        if (r)
                                return (r == SOCKET_E_EOF) ? CONNECTION_E_EOF : error_fold(r);

                        if (!input) {
                                *messagep = NULL;
                                return 0;
                        }

                        r = connection_feed_sasl(connection, input, n_input);
                        if (r)
                                return error_trace(r);
                } while (!connection->authenticated);
        }

        r = socket_dequeue(&connection->socket, messagep);
        if (r) {
                if (r == SOCKET_E_EOF)
                        return CONNECTION_E_EOF;
                else if (r == SOCKET_E_QUOTA)
                        return CONNECTION_E_QUOTA;

                return error_fold(r);
        }

        return 0;
}

/**
 * connection_queue() - XXX
 */
int connection_queue(Connection *connection, User *user, Message *message) {
        int r;

        r = socket_queue(&connection->socket, user, message);
        if (r == SOCKET_E_QUOTA)
                return CONNECTION_E_QUOTA;
        else if (r == SOCKET_E_SHUTDOWN)
                return 0;
        else if (r)
                return error_fold(r);

        dispatch_file_select(&connection->socket_file, EPOLLOUT);
        return 0;
}
