/*
 * Connection
 */

#include <c-macro.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include "connection.h"
#include "dbus/message.h"
#include "dbus/socket.h"
#include "user.h"
#include "util/dispatch.h"
#include "util/error.h"

static int connection_init(Connection *connection,
                           bool server,
                           DispatchContext *dispatch_ctx,
                           CList *dispatch_list,
                           CList *dispatch_hup,
                           DispatchFn dispatch_fn,
                           UserEntry *user,
                           int fd) {
        int r;

        *connection = (Connection)CONNECTION_NULL(*connection);
        connection->user = user_entry_ref(user);
        connection->hup_list = dispatch_hup;

        r = socket_init(&connection->socket, fd, server);
        if (r)
                return error_fold(r);

        r = dispatch_file_init(&connection->socket_file,
                               dispatch_ctx,
                               dispatch_list,
                               dispatch_fn,
                               fd,
                               EPOLLIN | EPOLLOUT);
        if (r)
                return error_fold(r);

        return 0;
}

/**
 * connection_init_server() - XXX
 */
int connection_init_server(Connection *connection,
                           DispatchContext *dispatch_ctx,
                           CList *dispatch_list,
                           CList *dispatch_hup,
                           DispatchFn dispatch_fn,
                           UserEntry *user,
                           const char *guid,
                           int fd) {
        _c_cleanup_(connection_deinitp) Connection *c = connection;
        int r;

        r = connection_init(c,
                            true,
                            dispatch_ctx,
                            dispatch_list,
                            dispatch_hup,
                            dispatch_fn,
                            user,
                            fd);
        if (r)
                return error_trace(r);

        c->server = true;
        sasl_server_init(&c->sasl.server, user->uid, guid);
        c = NULL;
        return 0;
}

/**
 * connection_init_client() - XXX
 */
int connection_init_client(Connection *connection,
                           DispatchContext *dispatch_ctx,
                           CList *dispatch_list,
                           CList *dispatch_hup,
                           DispatchFn dispatch_fn,
                           UserEntry *user,
                           int fd) {
        _c_cleanup_(connection_deinitp) Connection *c = connection;
        const char *request;
        size_t n_request;
        int r;

        r = connection_init(c,
                            false,
                            dispatch_ctx,
                            dispatch_list,
                            dispatch_hup,
                            dispatch_fn,
                            user,
                            fd);
        if (r)
                return error_trace(r);

        c->server = false;
        sasl_client_init(&c->sasl.client);

        r = sasl_client_dispatch(&c->sasl.client, NULL, 0, &request, &n_request);
        if (r)
                return error_fold(r);

        r = socket_queue_line(&c->socket, request, n_request);
        if (r)
                return error_fold(r);

        dispatch_file_select(&c->socket_file, EPOLLOUT);

        c = NULL;
        return 0;
}

/**
 * connection_deinit() - XXX
 */
void connection_deinit(Connection *connection) {
        if (connection->server)
                sasl_server_deinit(&connection->sasl.server);
        else
                sasl_client_deinit(&connection->sasl.client);
        c_list_unlink_init(&connection->hup_link);
        dispatch_file_deinit(&connection->socket_file);
        socket_deinit(&connection->socket);
        connection->user = user_entry_unref(connection->user);
}

static int connection_dispatch_line(Connection *connection, const char *input, size_t n_input) {
        const char *output = NULL;
        size_t n_output = 0;
        int r;

        if (connection->server) {
                r = sasl_server_dispatch(&connection->sasl.server, input, n_input, &output, &n_output);
                if (r)
                        return error_fold(r);

                connection->authenticated = sasl_server_is_done(&connection->sasl.server);
        } else {
                r = sasl_client_dispatch(&connection->sasl.client, input, n_input, &output, &n_output);
                if (r)
                        return error_fold(r);

                connection->authenticated = sasl_client_is_done(&connection->sasl.client);
        }

        if (output && n_output) {
                r = socket_queue_line(&connection->socket, output, n_output);
                if (r)
                        return error_fold(r);

                dispatch_file_select(&connection->socket_file, EPOLLOUT);
        }

        return 0;
}

int connection_dispatch_read(Connection *connection) {
        const char *input;
        size_t n_input;
        int r;

        r = socket_read(&connection->socket);
        if (!r) {
                /* kernel event handled, interest did not change */
                dispatch_file_clear(&connection->socket_file, EPOLLIN);
        } else if (r == SOCKET_E_LOST_INTEREST) {
                /* kernel event unknown, interest lost */
                dispatch_file_deselect(&connection->socket_file, EPOLLIN);
        } else if (r != SOCKET_E_PREEMPTED) {
                /* XXX: we should catch SOCKET_E_RESET here */
                return error_fold(r);
        }

        if (_c_unlikely_(!connection->authenticated)) {
                do {
                        r = socket_read_line(&connection->socket, &input, &n_input);
                        if (r || !input)
                                return error_fold(r);

                        r = connection_dispatch_line(connection, input, n_input);
                        if (r)
                                return (r > 0) ? r : error_fold(r);
                } while (!connection->authenticated);
        }

        return 0;
}

int connection_dispatch_write(Connection *connection) {
        int r;

        r = socket_write(&connection->socket);
        if (!r) {
                /* kernel event handled, interest did not change */
                dispatch_file_clear(&connection->socket_file, EPOLLOUT);
        } else if (r == SOCKET_E_LOST_INTEREST) {
                /* kernel event unknown, interest lost */
                dispatch_file_deselect(&connection->socket_file, EPOLLOUT);
        } else if (r != SOCKET_E_PREEMPTED) {
                /* XXX: we should catch SOCKET_E_RESET here */
                return error_fold(r);
        }

        return 0;
}

/**
 * connection_dequeue() - XXX
 */
int connection_dequeue(Connection *connection, Message **messagep) {
        int r;

        if (_c_likely_(!connection->hup)) {
                r = socket_read_message(&connection->socket, messagep);
                if (r <= 0)
                        return r;

                *messagep = message_unref(*messagep);
                /* XXX: HUP @connection */
        }

        return 0;
}

/**
 * connection_queue() - XXX
 */
int connection_queue(Connection *connection, SocketBuffer *skb) {
        socket_queue(&connection->socket, skb);

        dispatch_file_select(&connection->socket_file, EPOLLOUT);
        return 0;
}

/**
 * connection_queu_many() - XXX
 */
int connection_queue_many(Connection *connection, CList *skbs) {
        socket_queue_many(&connection->socket, skbs);

        dispatch_file_select(&connection->socket_file, EPOLLOUT);
        return 0;
}

/**
 * connection_queue_message() - XXX
 */
int connection_queue_message(Connection *connection, Message *message) {
        int r;

        r = socket_queue_message(&connection->socket, message);
        if (r)
                return error_fold(r);

        dispatch_file_select(&connection->socket_file, EPOLLOUT);
        return 0;
}
