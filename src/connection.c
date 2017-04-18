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

static int connection_sasl_client_dispatch(Connection *connection, const char *line) {
        switch (connection->sasl_client_state) {
        case SASL_CLIENT_STATE_AUTH:
                if (strcmp(line, "DATA") != 0)
                        return -EBADMSG;
                else {
                        connection->sasl_client_state = SASL_CLIENT_STATE_DATA;
                        return 0;
                }
        case SASL_CLIENT_STATE_DATA:
                if ((strncmp(line, "OK ", strlen("OK ")) != 0) ||
                    (strlen(line) != strlen("OK 0123456789abcdef0123456789abcdef")))
                        return -EBADMSG;
                else {
                        connection->sasl_client_state = SASL_CLIENT_STATE_UNIX_FD;
                        return 0;
                }
        case SASL_CLIENT_STATE_UNIX_FD:
                if (strcmp(line, "AGREE_UNIX_FD") != 0)
                        return -EBADMSG;
                else
                        return 1;
        }

        assert(false);
}

static int connection_dispatch_read_line(Connection *connection, DispatchFile *file) {
        const char *line, *reply = NULL;
        size_t n_line, n_reply = 0;
        int r;

        r = socket_read_line(connection->socket, &line, &n_line);
        if (r < 0)
                return r;

        if (connection->server)
                r = sasl_server_dispatch(&connection->sasl_server, line, n_line, &reply, &n_reply);
        else
                r = connection_sasl_client_dispatch(connection, line);
        if (r < 0)
                return r;
        else if (r > 0)
                connection->authenticated = true;

        if (reply) {
                r = socket_queue_line(connection->socket, reply, n_reply);
                if (r < 0)
                        return r;

                dispatch_file_select(file, EPOLLOUT);
        }

        return 0;
}

int connection_dispatch_read(Connection *connection, DispatchFile *file, Message **messagep) {
        Message *message = NULL;
        int r;

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
        int r;

        r = socket_new(&connection->socket, fd, server);
        if (r < 0)
                return r;

        connection->server = server;

        if (server) {
                sasl_server_init(&connection->sasl_server, uid, guid);
        } else {
                connection->sasl_client_state = SASL_CLIENT_STATE_AUTH;

                r = socket_queue_line(connection->socket, "AUTH EXTERNAL", strlen("AUTH EXTERNAL"));
                if (r < 0)
                        return r;

                r = socket_queue_line(connection->socket, "DATA", strlen("DATA"));
                if (r < 0)
                        return r;

                r = socket_queue_line(connection->socket, "NEGOTIATE UNIX FD", strlen("NEGOTIATE UNIX FD"));
                if (r < 0)
                        return r;

                r = socket_queue_line(connection->socket, "BEGIN", strlen("BEGIN"));
                if (r < 0)
                        return r;

                dispatch_file_select(file, EPOLLOUT);
        }

        return 0;
}

/**
 * connection_deinit() - XXX
 */
void connection_deinit(Connection *connection) {
        sasl_server_deinit(&connection->sasl_server);
        connection->socket = socket_free(connection->socket);
}
