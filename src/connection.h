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

struct Connection {
        Socket socket;
        union {
                SASLServer server;
                SASLClient client;
        } sasl;

        bool authenticated : 1;
        bool server : 1;
};

#define CONNECTION_NULL(_x) {                                                           \
                .socket = SOCKET_NULL((_x).socket),                                     \
                .sasl.server = SASL_SERVER_NULL,                                        \
                .server = false,                                                        \
        }

int connection_init(Connection *connection, DispatchFile *file, int fd, bool server, uid_t uid, const char *guid);
void connection_deinit(Connection *connection);

int connection_queue_message(Connection *connection, DispatchFile *file, Message *message);

int connection_dispatch_read(Connection *connection, DispatchFile *file, Message **messagep);
int connection_dispatch_write(Connection *connection, DispatchFile *file);
