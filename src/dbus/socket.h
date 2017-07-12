#pragma once

/*
 * D-Bus Socket Abstraction
 */

#include <c-list.h>
#include <c-macro.h>
#include <stdlib.h>
#include "dbus/message.h"
#include "util/user.h"

typedef struct FDList FDList;
typedef struct Socket Socket;
typedef struct SocketBuffer SocketBuffer;

#define SOCKET_LINE_PREALLOC (64UL) /* fits the longest sane SASL exchange */
#define SOCKET_LINE_MAX (16UL * 1024UL) /* taken from dbus-daemon(1) */
#define SOCKET_FD_MAX (253UL) /* taken from kernel SCM_MAX_FD */
#define SOCKET_MMSG_MAX (16) /* randomly picked, no tuning done so far */
#define SOCKET_DATA_RECV_MAX (2UL * 1024UL) /* based on measured message sized */

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

        bool lines_done : 1;
        bool shutdown : 1;
        bool reset : 1;
        bool hup_in : 1;
        bool hup_out : 1;

        struct SocketIn {
                UserCharge charge_buf_data;
                UserCharge charge_buf_fds;
                UserCharge charge_msg_data;
                UserCharge charge_msg_fds;

                char *data;
                size_t data_size;
                size_t data_start;
                size_t data_end;
                size_t cursor;

                FDList *fds;
                Message *pending_message;
        } in;

        struct SocketOut {
                CList queue;
        } out;

        /* keep last to improve member-locality */
        char input_buffer[SOCKET_DATA_RECV_MAX];
};

#define SOCKET_NULL(_x) {                                               \
                .fd = -1,                                               \
                .in.charge_buf_data = USER_CHARGE_INIT,                 \
                .in.charge_buf_fds = USER_CHARGE_INIT,                  \
                .in.charge_msg_data = USER_CHARGE_INIT,                 \
                .in.charge_msg_fds = USER_CHARGE_INIT,                  \
                .out.queue = C_LIST_INIT((_x).out.queue),               \
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

C_DEFINE_CLEANUP(Socket *, socket_deinit);

/* inline helpers */

static inline bool socket_is_running(Socket *socket) {
        return !socket->reset;
}
