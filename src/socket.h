#pragma once

/*
 * D-Bus Socket Abstraction
 */

#include <c-macro.h>
#include <stdlib.h>
#include <c-list.h>

typedef struct Message Message;
typedef struct Socket Socket;

#define SOCKET_LINE_MAX (16UL * 1024UL) /* taken from dbus-daemon(1) */
#define SOCKET_FD_MAX (253UL) /* taken from kernel SCM_MAX_FD */

struct Socket {
        int fd;

        bool lines_done : 1;

        struct SocketIn {
                bool null_byte_done : 1;

                int *fds;
                size_t n_fds;

                char *data;
                size_t data_size;
                size_t data_start;
                size_t data_end;
                size_t data_pos;

                Message *pending_message;
        } in;

        struct SocketOut {
                CList lines;
                CList messages;
        } out;
};

int socket_new(Socket **socketp, int fd);
Socket *socket_free(Socket *socket);

int socket_read_line(Socket *socket, char **linep, size_t *np);
int socket_read_message(Socket *socket, Message **messagep);

int socket_queue_line(Socket *socket, size_t n_bytes, char **linep, size_t **posp);
int socket_queue_message(Socket *socket, Message *message);

int socket_write(Socket *socket);

C_DEFINE_CLEANUP(Socket *, socket_free);
