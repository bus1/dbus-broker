#pragma once

/*
 * Connection
 */

#include <c-list.h>
#include <stdlib.h>
#include <sys/types.h>
#include "dbus/sasl.h"
#include "util/dispatch.h"

typedef struct Connection Connection;
typedef struct Message Message;
typedef struct Socket Socket;

struct Connection {
        bool authenticated : 1;
        bool server : 1;

        union {
                SASLServer server;
                SASLClient client;
        } sasl;

        Socket *socket;
};

#define CONNECTION_NULL(_x) {                                                           \
                .dispatch_file = (DispatchFile)DISPATCH_FILE_NULL((_x).dispatch_file)   \
        }

int connection_init(Connection *connection, DispatchFile *file, int fd, bool server, uid_t uid, const char *guid);
void connection_deinit(Connection *connection);

int connection_queue_message(Connection *connection, DispatchFile *file, Message *message);

int connection_dispatch_read(Connection *connection, DispatchFile *file, Message **messagep);
int connection_dispatch_write(Connection *connection, DispatchFile *file);
