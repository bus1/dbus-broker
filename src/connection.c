/*
 * Connection
 */

#include <c-macro.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include "connection.h"
#include "socket.h"
#include "util/dispatch.h"
#include "util/error.h"

static int connection_dispatch_line(Connection *connection, DispatchFile *file, const char *input, size_t n_input) {
        const char *output = NULL;
        size_t n_output = 0;
        int r;

        if (connection->server) {
                r = sasl_server_dispatch(&connection->sasl_server, input, n_input, &output, &n_output);
                if (r)
                        return error_fold(r);

                connection->authenticated = sasl_server_is_done(&connection->sasl_server);
        } else {
                r = sasl_client_dispatch(&connection->sasl_client, input, n_input, &output, &n_output);
                if (r)
                        return error_fold(r);

                connection->authenticated = sasl_client_is_done(&connection->sasl_client);
        }

        if (output && n_output) {
                r = socket_queue_line(connection->socket, output, n_output);
                if (r)
                        return error_fold(r);

                dispatch_file_select(file, EPOLLOUT);
        }

        return 0;
}

int connection_dispatch_read(Connection *connection, DispatchFile *file, Message **messagep) {
        const char *input;
        size_t n_input;
        int r;

        r = socket_read(connection->socket);
        if (!r) {
                /* kernel event handled, interest did not change */
                dispatch_file_clear(file, EPOLLIN);
        } else if (r == SOCKET_E_LOST_INTEREST) {
                /* kernel event unknown, interest lost */
                dispatch_file_deselect(file, EPOLLIN);
        } else if (r != SOCKET_E_PREEMPTED) {
                /* XXX: we should catch SOCKET_E_RESET here */
                return error_fold(r);
        }

        if (_c_unlikely_(!connection->authenticated)) {
                do {
                        r = socket_read_line(connection->socket, &input, &n_input);
                        if (r)
                                return error_fold(r);

                        if (!input) {
                                dispatch_file_clear(file, EPOLLIN);
                                return 0;
                        }

                        r = connection_dispatch_line(connection, file, input, n_input);
                        if (r)
                                return (r > 0) ? r : error_fold(r);
                } while (!connection->authenticated);
        }

        r = socket_read_message(connection->socket, messagep);
        if (r)
                return error_fold(r);

        if (!*messagep)
                dispatch_file_clear(file, EPOLLIN);

        return 0;
}

int connection_dispatch_write(Connection *connection, DispatchFile *file) {
        int r;

        r = socket_write(connection->socket);
        if (!r) {
                /* kernel event handled, interest did not change */
                dispatch_file_clear(file, EPOLLOUT);
        } else if (r == SOCKET_E_LOST_INTEREST) {
                /* kernel event unknown, interest lost */
                dispatch_file_deselect(file, EPOLLOUT);
        } else if (r != SOCKET_E_PREEMPTED) {
                /* XXX: we should catch SOCKET_E_RESET here */
                return error_fold(r);
        }

        return 0;
}

/**
 * connection_queue_message() - XXX
 */
int connection_queue_message(Connection *connection, DispatchFile *file, Message *message) {
        int r;

        r = socket_queue_message(connection->socket, message);
        if (r)
                return error_fold(r);

        dispatch_file_select(file, EPOLLOUT);

        return 0;
}

/**
 * connection_init() - XXX
 */
int connection_init(Connection *connection, DispatchFile *file, int fd, bool server, uid_t uid, const char *guid) {
        const char *request;
        size_t n_request;
        int r;

        r = socket_new(&connection->socket, fd, server);
        if (r < 0)
                return error_fold(r);

        connection->server = server;

        if (server) {
                sasl_server_init(&connection->sasl_server, uid, guid);
        } else {
                sasl_client_init(&connection->sasl_client);

                r = sasl_client_dispatch(&connection->sasl_client, NULL, 0, &request, &n_request);
                if (r)
                        return error_fold(r);

                r = socket_queue_line(connection->socket, request, n_request);
                if (r)
                        return error_fold(r);

                dispatch_file_select(file, EPOLLOUT);
        }

        return 0;
}

/**
 * connection_deinit() - XXX
 */
void connection_deinit(Connection *connection) {
        if (connection->server)
                sasl_server_deinit(&connection->sasl_server);
        else
                sasl_client_deinit(&connection->sasl_client);
        connection->socket = socket_free(connection->socket);
}
