#pragma once

/*
 * Connection
 */

#include <c-list.h>
#include <stdlib.h>
#include <sys/types.h>
#include "dbus/sasl.h"
#include "dbus/socket.h"
#include "util/dispatch.h"

typedef struct Connection Connection;
typedef struct Message Message;
typedef struct User User;

enum {
        _CONNECTION_E_SUCCESS,

        CONNECTION_E_RESET,
        CONNECTION_E_EOF,

        CONNECTION_E_QUOTA,
};

struct Connection {
        Socket socket;
        DispatchFile socket_file;
        union {
                SASLServer server;
                SASLClient client;
        } sasl;

        bool server : 1;
        bool hangup : 1;
        bool lingering : 1;
        bool authenticated : 1;

        uint64_t transaction_id;
};

#define CONNECTION_NULL(_x) {                                           \
                .socket = SOCKET_NULL((_x).socket),                     \
                .socket_file = DISPATCH_FILE_NULL((_x).socket_file),    \
                .sasl.client = SASL_CLIENT_NULL,                        \
                .server = false,                                        \
        }

int connection_init_server(Connection *connection,
                           DispatchContext *dispatch_ctx,
                           DispatchFn dispatch_fn,
                           User *user,
                           const char *guid,
                           int fd);
int connection_init_client(Connection *connection,
                           DispatchContext *dispatch_ctx,
                           DispatchFn dispatch_fn,
                           User *user,
                           int fd);
void connection_deinit(Connection *connection);

int connection_open(Connection *connection);
void connection_shutdown(Connection *connection);
void connection_close(Connection *connection);
int connection_dispatch(Connection *connection, uint32_t events);

int connection_dequeue(Connection *connection, Message **messagep);
int connection_queue(Connection *connection, User *user, uint64_t transaction_id, Message *message);

C_DEFINE_CLEANUP(Connection *, connection_deinit);

/* inline helpers */

static inline bool connection_is_running(Connection *connection) {
        return socket_is_running(&connection->socket);
}
