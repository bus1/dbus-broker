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
typedef struct UserEntry UserEntry;

enum {
        _CONNECTION_E_SUCCESS,

        CONNECTION_E_RESET,
        CONNECTION_E_EOF,
};

struct Connection {
        UserEntry *user;
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
};

#define CONNECTION_NULL(_x) {                                           \
                .socket = SOCKET_NULL((_x).socket),                     \
                .socket_file = DISPATCH_FILE_NULL((_x).socket_file),    \
                .sasl.client = SASL_CLIENT_NULL,                        \
                .server = false,                                        \
        }

int connection_init_server(Connection *connection,
                           DispatchContext *dispatch_ctx,
                           CList *dispatch_list,
                           DispatchFn dispatch_fn,
                           UserEntry *user,
                           const char *guid,
                           int fd);
int connection_init_client(Connection *connection,
                           DispatchContext *dispatch_ctx,
                           CList *dispatch_list,
                           DispatchFn dispatch_fn,
                           UserEntry *user,
                           int fd);
void connection_deinit(Connection *connection);

int connection_open(Connection *connection);
void connection_shutdown(Connection *connection);
void connection_close(Connection *connection);
int connection_dispatch(Connection *connection, uint32_t events);

int connection_dequeue(Connection *connection, Message **messagep);
int connection_queue(Connection *connection, SocketBuffer *skb);
int connection_queue_message(Connection *connection, Message *message);

C_DEFINE_CLEANUP(Connection *, connection_deinit);

/* inline helpers */

static inline bool connection_is_running(Connection *connection) {
        return socket_is_running(&connection->socket);
}
