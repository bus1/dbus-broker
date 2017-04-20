#pragma once

/*
 * D-Bus Socket Abstraction
 */

#include <c-list.h>
#include <c-macro.h>
#include <stdlib.h>

typedef struct FDList FDList;
typedef struct Message Message;
typedef struct Socket Socket;
typedef struct SocketBuffer SocketBuffer;

#define SOCKET_LINE_PREALLOC (2UL * 1024UL) /* XXX */
#define SOCKET_LINE_MAX (16UL * 1024UL) /* taken from dbus-daemon(1) */
#define SOCKET_FD_MAX (253UL) /* taken from kernel SCM_MAX_FD */
#define SOCKET_MMSG_MAX (16) /* XXX */
#define SOCKET_DATA_PREALLOC (2UL * 1024UL) /* XXX */

enum {
        _SOCKET_E_SUCCESS,

        /* I/O handling */
        SOCKET_E_LOST_INTEREST,
        SOCKET_E_PREEMPTED,

        /* socket errors */
        SOCKET_E_RESET,
        SOCKET_E_OVERLONG_LINE,
        SOCKET_E_SPLIT_FDS,
        SOCKET_E_NO_NULL_BYTE,
        SOCKET_E_OVERLONG_MESSAGE,
        SOCKET_E_CORRUPT_MESSAGE,
};

struct SocketBuffer {
        CList link;

        size_t n_total;
        Message *message;

        size_t n_vecs;
        struct iovec *writer;
        struct iovec vecs[];
};

struct Socket {
        int fd;
        bool server : 1;

        bool null_byte_done : 1;
        bool lines_done : 1;

        struct SocketIn {
                char *data;
                size_t data_size;
                size_t data_start;
                size_t data_end;
                size_t data_pos;

                FDList *fds;
                Message *pending_message;
        } in;

        struct SocketOut {
                CList queue;
        } out;
};

/* socket buffer */

int socket_buffer_new_message(SocketBuffer **bufferp, Message *message);
SocketBuffer *socket_buffer_free(SocketBuffer *buffer);

C_DEFINE_CLEANUP(SocketBuffer *, socket_buffer_free);

/* socket IO */

int socket_new(Socket **socketp, int fd, bool server);
Socket *socket_free(Socket *socket);

int socket_read_line(Socket *socket, const char **linep, size_t *np);
int socket_read_message(Socket *socket, Message **messagep);

void socket_queue(Socket *socket, SocketBuffer *buffer);
void socket_queue_many(Socket *socket, CList *list);
int socket_queue_line(Socket *socket, const char *line, size_t n);
int socket_queue_message(Socket *socket, Message *message);

int socket_read(Socket *socket);
int socket_write(Socket *socket);

C_DEFINE_CLEANUP(Socket *, socket_free);

/* inline helpers */

static inline bool socket_has_input(Socket *socket) {
        return socket->in.data_pos < socket->in.data_end;
}

static inline bool socket_has_output(Socket *socket) {
        return !c_list_is_empty(&socket->out.queue);
}
