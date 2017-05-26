#pragma once

/*
 * D-Bus Socket Abstraction
 */

#include <c-list.h>
#include <c-macro.h>
#include <stdlib.h>
#include "dbus/message.h"

typedef struct FDList FDList;
typedef struct Socket Socket;
typedef struct SocketBuffer SocketBuffer;

#define SOCKET_LINE_PREALLOC (64UL) /* fits the longest sane SASL exchange */
#define SOCKET_LINE_MAX (16UL * 1024UL) /* taken from dbus-daemon(1) */
#define SOCKET_FD_MAX (253UL) /* taken from kernel SCM_MAX_FD */
#define SOCKET_MMSG_MAX (16) /* XXX */
#define SOCKET_DATA_RECV_MAX (2UL * 1024UL) /* XXX */

enum {
        _SOCKET_E_SUCCESS,

        /* I/O handling */
        SOCKET_E_LOST_INTEREST,
        SOCKET_E_PREEMPTED,

        /* socket errors */
        SOCKET_E_RESET,
        SOCKET_E_EOF,
};

/* socket buffer */

struct SocketBuffer {
        CList link;

        size_t n_total;
        Message *message;

        size_t n_vecs;
        struct iovec *writer;
        struct iovec vecs[];
};

int socket_buffer_new(SocketBuffer **bufferp, Message *message);
SocketBuffer *socket_buffer_free(SocketBuffer *buffer);

C_DEFINE_CLEANUP(SocketBuffer *, socket_buffer_free);

/* socket IO */

struct Socket {
        int fd;

        bool lines_done : 1;
        bool shutdown : 1;
        bool hup_in : 1;
        bool hup_out : 1;

        struct SocketIn {
                char *data;
                size_t data_size;
                size_t data_start;
                size_t data_end;

                FDList *fds;

                union {
                        size_t line_cursor;
                        Message *pending_message;
                };
        } in;

        struct SocketOut {
                CList queue;
        } out;
};

#define SOCKET_NULL(_x) {                                               \
                .fd = -1,                                               \
                .out.queue = C_LIST_INIT((_x).out.queue),               \
        }

int socket_init(Socket *socket, int fd);
void socket_deinit(Socket *socket);

int socket_dequeue_line(Socket *socket, const char **linep, size_t *np);
int socket_dequeue(Socket *socket, Message **messagep);

int socket_queue_line(Socket *socket, const char *line, size_t n);
void socket_queue(Socket *socket, SocketBuffer *buffer);

int socket_dispatch(Socket *socket, uint32_t event);
void socket_shutdown(Socket *socket);
void socket_close(Socket *socket);

C_DEFINE_CLEANUP(Socket *, socket_deinit);

/* inline helpers */

static inline bool socket_has_input(Socket *socket) {
        if (_c_unlikely_(!socket->lines_done))
                return socket->in.line_cursor < socket->in.data_end;
        else
                return socket->in.data_end - socket->in.data_start >= sizeof(MessageHeader);
}

static inline bool socket_has_output(Socket *socket) {
        return !c_list_is_empty(&socket->out.queue);
}

static inline bool socket_is_running(Socket *socket) {
        return !socket->hup_out || !socket->hup_in || socket_has_input(socket);
}
