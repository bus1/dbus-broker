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

static int connection_dispatch_read_line(Connection *connection, DispatchFile *file) {
        const char *input, *output = NULL;
        size_t n_input, n_output = 0;
        int r;

        r = socket_read_line(connection->socket, &input, &n_input);
        if (r)
                return (r > 0) ? -ENOTRECOVERABLE : r;

        if (connection->server) {
                r = sasl_server_dispatch(&connection->sasl_server, input, n_input, &output, &n_output);
                if (r > 0)
                        connection->authenticated = true;
                else if (r)
                        return (r > 0) ? -ENOTRECOVERABLE : r;
        } else {
                r = sasl_client_dispatch(&connection->sasl_client, input, n_input, &output, &n_output);
                if (r)
                        return (r > 0) ? -ENOTRECOVERABLE : r;

                connection->authenticated = sasl_client_is_done(&connection->sasl_client);
        }

        if (output && n_output) {
                r = socket_queue_line(connection->socket, output, n_output);
                if (r)
                        return (r > 0) ? -ENOTRECOVERABLE : r;

                dispatch_file_select(file, EPOLLOUT);
        }

        return 0;
}

int connection_dispatch_read(Connection *connection, DispatchFile *file, Message **messagep) {
        Message *message = NULL;
        int r;

        /*
         * Under normal operation we expect to receive at most four SASL lines and a message
         * before breaking. There is no limit to the number of SASL exchnages however, and
         * there is no harm in trying to process some more lines. If SASL has still not
         * completed by the time we break, we return @message=NULL to indicate to the caller
         * not to retry before going into poll again, so this cannot really be exploited.
         */
        for (unsigned int i = 0; i < 32; i ++) {
                if (_c_likely_(connection->authenticated)) {
                        r = socket_read_message(connection->socket, &message);
                        if (r >= 0)
                                break;
                } else {
                        r = connection_dispatch_read_line(connection, file);
                }
                if (r == -EAGAIN)
                        dispatch_file_clear(file, EPOLLIN);
                else if (r < 0)
                        return r;
        }

        *messagep = message;
        return 0;
}

int connection_dispatch_write(Connection *connection, DispatchFile *file) {
        int r;

        r = socket_write(connection->socket);
        if (r == -EAGAIN) {
                /* not able to write more */
                dispatch_file_clear(file, EPOLLOUT);
                return 0;
        } else if (r == 0) {
                /* nothing more to write */
                dispatch_file_deselect(file, EPOLLOUT);
        } else if (r < 0) {
                /* XXX: swallow error code and tear down this peer */
                return 0;
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
                return (r > 0) ? -ENOTRECOVERABLE : r;

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
                return r;

        connection->server = server;

        if (server) {
                sasl_server_init(&connection->sasl_server, uid, guid);
        } else {
                sasl_client_init(&connection->sasl_client);

                r = sasl_client_dispatch(&connection->sasl_client, NULL, 0, &request, &n_request);
                if (r)
                        return (r > 0) ? -ENOTRECOVERABLE : r;

                r = socket_queue_line(connection->socket, request, n_request);
                if (r)
                        return (r > 0) ? -ENOTRECOVERABLE : r;

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
