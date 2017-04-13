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

        bool lines_done : 1;

        struct SocketIn {
                bool null_byte_done : 1;

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

int socket_new(Socket **socketp, int fd);
Socket *socket_free(Socket *socket);

int socket_read_line(Socket *socket, char **linep, size_t *np);
int socket_read_message(Socket *socket, Message **messagep);

int socket_queue_line(Socket *socket, size_t n_bytes, char **linep, size_t **posp);
int socket_queue_message(Socket *socket, Message *message);

int socket_write(Socket *socket);

C_DEFINE_CLEANUP(Socket *, socket_free);
