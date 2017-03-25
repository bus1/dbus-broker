#pragma once

/*
 * D-Bus Socket Abstraction
 */

#include <c-macro.h>
#include <stdlib.h>
#include <c-list.h>

typedef struct DBusMessage DBusMessage;
typedef struct DBusSocket DBusSocket;

#define DBUS_SOCKET_LINE_MAX (16UL * 1024UL) /* taken from dbus-daemon(1) */
#define DBUS_SOCKET_FD_MAX (253UL) /* taken from kernel SCM_MAX_FD */

struct DBusSocket {
        int fd;

        struct DBusSocketIn {
                bool null_byte_done : 1;
                bool lines_done : 1;

                int *fds;
                size_t n_fds;

                char *data;
                size_t data_size;
                size_t data_start;
                size_t data_end;
                size_t data_pos;

                DBusMessage *pending_message;
        } in;

        struct DBusSocketOut {
                bool lines_done : 1;

                CList lines;
                CList messages;
        } out;
};

int dbus_socket_new(DBusSocket **socketp, int fd);
DBusSocket *dbus_socket_free(DBusSocket *socket);

int dbus_socket_read_line(DBusSocket *socket, char **linep, size_t *np);
int dbus_socket_read_message(DBusSocket *socket, DBusMessage **messagep);

int dbus_socket_reserve_line(DBusSocket *socket,
                             size_t n_bytes,
                             char **linep,
                             size_t **posp);
int dbus_socket_queue_message(DBusSocket *socket, DBusMessage *message);

C_DEFINE_CLEANUP(DBusSocket *, dbus_socket_free);
