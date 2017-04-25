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

        r = socket_init(&connection->socket, fd);
        if (r)
                return error_fold(r);

        r = dispatch_file_init(&connection->socket_file,
                               dispatch_ctx,
                               dispatch_list,
                               dispatch_fn,
                               fd,
                               EPOLLHUP | EPOLLIN | EPOLLOUT);
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
        int r;

        r = connection_init(c,
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

static void connection_hangup(Connection *connection) {
        connection->hangup = true;
        if (!socket_is_running(&connection->socket))
                dispatch_file_deselect(&connection->socket_file, EPOLLHUP | EPOLLIN | EPOLLOUT);
        if (!c_list_is_linked(&connection->hup_link))
                c_list_link_tail(connection->hup_list, &connection->hup_link);
}

/**
 * connection_start() - XXX
 */
int connection_start(Connection *connection) {
        uint32_t events = EPOLLHUP | EPOLLIN;
        const char *request = NULL;
        size_t n_request;
        int r;

        assert(socket_is_running(&connection->socket));

        if (!connection->server) {
                events |= EPOLLOUT;

                r = sasl_client_dispatch(&connection->sasl.client, NULL, 0, &request, &n_request);
                if (r)
                        return error_fold(r);

                if (request) {
                        r = socket_queue_line(&connection->socket, request, n_request);
                        if (r)
                                return error_fold(r);
                }
        }

        dispatch_file_select(&connection->socket_file, events);
        return 0;
}

/**
 * connection_stop() - XXX
 */
void connection_stop(Connection *connection) {
        socket_close(&connection->socket);
        connection_hangup(connection);
}

/**
 * connection_dispatch() - XXX
 */
int connection_dispatch(Connection *connection, uint32_t event) {
        int r;

        r = socket_dispatch(&connection->socket, event);
        if (!r)
                dispatch_file_clear(&connection->socket_file, event);
        else if (r == SOCKET_E_LOST_INTEREST)
                dispatch_file_deselect(&connection->socket_file, event);
        else if (r == SOCKET_E_RESET)
                connection_hangup(connection);
        else if (r != SOCKET_E_PREEMPTED)
                return error_fold(r);

        return 0;
}

static int connection_feed_sasl(Connection *connection, const char *input, size_t n_input) {
        const char *output = NULL;
        size_t n_output = 0;
        int r;

        assert(!connection->authenticated);

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
                        if (r || !input) {
                                if (r > 0) {
                                        /* XXX: distinguish the different errors? */
                                        connection_hangup(connection);
                                        *messagep = NULL;
                                        r = 0;
                                }
                                return error_fold(r);
                        }

                        r = connection_feed_sasl(connection, input, n_input);
                        if (r)
                                return error_trace(r);
                } while (!connection->authenticated);
        }

        r = socket_dequeue(&connection->socket, messagep);
        if (r > 0) {
                /* XXX: distinguish the different errors? */
                connection_hangup(connection);
                *messagep = NULL;
                r = 0;
        }

        return r;
}

/**
 * connection_queue_many() - XXX
 */
int connection_queue_many(Connection *connection, CList *skbs) {
        socket_queue_many(&connection->socket, skbs);
        if (socket_has_output(&connection->socket))
                dispatch_file_select(&connection->socket_file, EPOLLOUT);
        return 0;
}

/**
 * connection_queue() - XXX
 */
int connection_queue(Connection *connection, SocketBuffer *skb) {
        CList list = C_LIST_INIT(list);
        int r;

        c_list_link_tail(&list, &skb->link);
        r = connection_queue_many(connection, &list);
        if (r)
                c_list_unlink_init(&skb->link);

        return error_fold(r);
}

/**
 * connection_queue_message() - XXX
 */
int connection_queue_message(Connection *connection, Message *message) {
        SocketBuffer *skb;
        int r;

        r = socket_buffer_new_message(&skb, message);
        if (r)
                return error_fold(r);

        r = connection_queue(connection, skb);
        if (r)
                socket_buffer_free(skb);

        return error_fold(r);
}
