#pragma once

/*
 * D-Bus Socket Abstraction
 */

#include <c-list.h>
#include <c-stdaux.h>
#include <stdlib.h>
#include "dbus/message.h"
#include "dbus/queue.h"
#include "util/user.h"

typedef struct FDList FDList;
typedef struct Socket Socket;
typedef struct SocketBuffer SocketBuffer;

#define SOCKET_LINE_PREALLOC (64UL) /* fits the longest sane SASL exchange */
#define SOCKET_FD_MAX (253UL) /* taken from kernel SCM_MAX_FD */
#define SOCKET_MMSG_MAX (16) /* randomly picked, no tuning done so far */

enum {
        _SOCKET_E_SUCCESS,

        /* I/O handling */
        SOCKET_E_LOST_INTEREST,
        SOCKET_E_PREEMPTED,

        /* socket errors */
        SOCKET_E_EOF,
        SOCKET_E_QUOTA,
        SOCKET_E_SHUTDOWN,
};

/* socket IO */

struct Socket {
        User *user;
        int fd;

        bool shutdown : 1;
        bool reset : 1;
        bool hup_in : 1;
        bool hup_out : 1;

        struct {
                IQueue queue;
                MessageHeader header;
                Message *message;
        } in;

        struct SocketOut {
                CList queue;
                CList pending;
        } out;
};

#define SOCKET_NULL(_x) {                                               \
                .fd = -1,                                               \
                .in.queue = IQUEUE_NULL((_x).in.queue),                 \
                .out.queue = C_LIST_INIT((_x).out.queue),               \
                .out.pending = C_LIST_INIT((_x).out.pending),           \
        }

void socket_init(Socket *socket, User *user, int fd);
void socket_deinit(Socket *socket);

int socket_dequeue_line(Socket *socket, const char **linep, size_t *np);
int socket_dequeue(Socket *socket, Message **messagep);

int socket_queue_line(Socket *socket, User *user, const char *line, size_t n);
int socket_queue(Socket *socket, User *user, Message *message);

int socket_dispatch(Socket *socket, uint32_t event);
void socket_shutdown(Socket *socket);
void socket_close(Socket *socket);
void socket_get_stats(Socket *socket,
                      unsigned int *n_in_bytesp,
                      unsigned int *n_in_fdsp,
                      unsigned int *n_out_bytesp,
                      unsigned int *n_out_fdsp);

C_DEFINE_CLEANUP(Socket *, socket_deinit);

/* inline helpers */

static inline bool socket_is_running(Socket *socket) {
        return !socket->reset;
}
