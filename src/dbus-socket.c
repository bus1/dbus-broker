/*
 * D-Bus Socket Abstraction
 *
 * The DBusSocket objects wraps a single connection between two DBus peers
 * using streaming sockets. File-desciptor management is done by the caller.
 * This object is mainly used for line and message buffering. It supports
 * dual-mode: Line-based buffers for initial SASL transactions, and
 * message-based buffers for DBus transactions.
 *
 * Note that once the first real DBus message was read, you must not use the
 * line-helpers, anymore!
 */

#include <c-list.h>
#include <c-macro.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include "dbus-socket.h"
#include "dbus-message.h"

typedef struct DBusSocketLineBuffer DBusSocketLineBuffer;
typedef struct DBusSocketMessageEntry DBusSocketMessageEntry;

struct DBusSocketLineBuffer {
        CList link;
        size_t data_size;
        size_t data_pos;
        char data[];
};

struct DBusSocketMessageEntry {
        CList link;
        DBusMessage *message;
};

static int dbus_socket_line_buffer_new(DBusSocketLineBuffer **bufferp,
                                       DBusSocket *socket,
                                       size_t n_bytes) {
        DBusSocketLineBuffer *buffer;

        n_bytes = C_MAX(n_bytes, 2048);

        buffer = calloc(1, sizeof(*buffer) + n_bytes);
        if (!buffer)
                return -ENOMEM;

        buffer->data_size = n_bytes;
        c_list_link_tail(&socket->out.lines, &buffer->link);

        *bufferp = buffer;
        return 0;
}

static DBusSocketLineBuffer *
dbus_socket_line_buffer_free(DBusSocketLineBuffer *buffer) {
        c_list_unlink(&buffer->link);
        free(buffer);
        return NULL;
}


static DBusSocketMessageEntry *
dbus_socket_message_entry_free(DBusSocketMessageEntry *entry) {
        dbus_message_unref(entry->message);
        c_list_unlink(&entry->link);
        free(entry);
        return NULL;
}

int dbus_socket_new(DBusSocket **socketp, int fd) {
        _c_cleanup_(dbus_socket_freep) DBusSocket *socket = NULL;

        socket = calloc(1, sizeof(*socket));
        if (!socket)
                return -ENOMEM;

        socket->fd = fd;

        socket->out.lines = (CList)C_LIST_INIT(socket->out.lines);
        socket->out.messages = (CList)C_LIST_INIT(socket->out.messages);

        socket->in.data_size = 2048;
        socket->in.data = malloc(socket->in.data_size);
        if (!socket->in.data)
                return -ENOMEM;

        *socketp = socket;
        socket = NULL;
        return 0;
}

DBusSocket *dbus_socket_free(DBusSocket *socket) {
        DBusSocketLineBuffer *line;
        DBusSocketMessageEntry *entry;

        if (!socket)
                return NULL;

        while (socket->in.n_fds)
                close(socket->in.fds[--socket->in.n_fds]);

        socket->fd = c_close(socket->fd);

        while ((line = c_list_first_entry(&socket->out.lines,
                                         DBusSocketLineBuffer,
                                         link)))
                dbus_socket_line_buffer_free(line);

        while ((entry = c_list_first_entry(&socket->out.messages,
                                         DBusSocketMessageEntry,
                                         link)))
                dbus_socket_message_entry_free(entry);

        dbus_message_unref(socket->in.pending_message);
        free(socket->in.data);
        free(socket->in.fds);
        free(socket);

        return NULL;
}

static int dbus_socket_recvmsg(int fd,
                               void *buffer,
                               size_t *from,
                               size_t *to,
                               int **fdsp,
                               size_t *n_fdsp) {
        union {
                struct cmsghdr cmsg;
                char buffer[CMSG_SPACE(sizeof(int) * DBUS_SOCKET_FD_MAX)];
        } control;
        struct cmsghdr *cmsg;
        struct msghdr msg;
        int r, *fds = NULL;
        size_t n_fds = 0;
        ssize_t l;

        assert(*to > *from);

        msg = (struct msghdr){
                .msg_iov = &(struct iovec){
                        .iov_base = buffer + *from,
                        .iov_len = *to - *from,
                },
                .msg_iovlen = 1,
                .msg_control = &control,
                .msg_controllen = sizeof(control),
        };

        l = recvmsg(fd, &msg, MSG_DONTWAIT | MSG_CMSG_CLOEXEC);
        if (_c_unlikely_(l <= 0))
                return (l < 0) ? -errno : -ECONNRESET;

        for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
                if (cmsg->cmsg_level == SOL_SOCKET &&
                    cmsg->cmsg_type == SCM_RIGHTS) {
                        /*
                         * Kernel breaks after SKB+fd, so we never get more
                         * than one SCM_RIGHTS array.
                         */
                        assert(!n_fds);
                        fds = (void *)CMSG_DATA(cmsg);
                        n_fds = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);
                        assert(n_fds <= DBUS_SOCKET_FD_MAX);
                } else {
                        /* XXX: debug message? */
                }
        }

        if (_c_unlikely_(n_fds)) {
                if (*n_fdsp) {
                        r = -EBADMSG;
                        goto error;
                }

                *fdsp = malloc(n_fds * sizeof(int));
                if (!*fdsp) {
                        r = -ENOMEM;
                        goto error;
                }

                memcpy(*fdsp, fds, n_fds * sizeof(int));
                *n_fdsp = n_fds;
        }

        *from += l;
        return 0;

error:
        while (n_fds)
                close(fds[--n_fds]);
        return r;
}

static int dbus_socket_line_pop(DBusSocket *socket, char **linep, size_t *np) {
        char *line;
        size_t n;

        /* skip the very first byte of the stream, which must be 0 */
        if (_c_unlikely_(!socket->in.null_byte_done) &&
            socket->in.data_pos < socket->in.data_end) {
                if (socket->in.data[socket->in.data_pos] != '\0')
                        return -EBADMSG;

                socket->in.data_start = ++socket->in.data_pos;
                socket->in.null_byte_done = true;
        }

        /*
         * Advance our cursor byte by byte and look for an end-of-line. We
         * remember the parser position, so no byte is ever parsed twice.
         */
        for ( ; socket->in.data_pos < socket->in.data_end; ++socket->in.data_pos) {
                /*
                 * We are at the end of the socket buffer, hence we must
                 * consume any possible FD array that we recveived alongside
                 * it. The kernel always breaks _after_ skbs with FDs, but not
                 * before them. Hence, FDs are attached to the LAST byte of our
                 * socket buffer, rather than the first.
                 *
                 * During line-handling, we silently ignore any received FDs,
                 * and the DBus spec clearly states that no extension shall
                 * pass FDs during authentication.
                 */
                if (socket->in.data_pos + 1 == socket->in.data_end &&
                    _c_unlikely_(socket->in.n_fds)) {
                        while (socket->in.n_fds)
                                close(socket->in.fds[--socket->in.n_fds]);

                        socket->in.fds = c_free(socket->in.fds);
                }

                /*
                 * If we find an \r\n, advance the start indicator and return
                 * a pointer to the caller so they can parse the line.
                 * We do NOT copy the line. We leave it in the buffer untouched
                 * and return a direct pointer into the buffer. The pointer is
                 * only valid until the next call into this DBusSocket object.
                 */
                if (socket->in.data_pos > 0 &&
                    socket->in.data[socket->in.data_pos] == '\n' &&
                    socket->in.data[socket->in.data_pos - 1] == '\r') {
                        /* remember start and length without \r\n */
                        line = socket->in.data + socket->in.data_start;
                        n = socket->in.data_pos - socket->in.data_start - 1;

                        /* forward iterator */
                        socket->in.data_start = ++socket->in.data_pos;

                        /* replace \r by safety NUL and return to caller */
                        line[n] = 0;
                        *linep = line;
                        *np = n;
                        return 0;
                }
        }

        return -EAGAIN;
}

static int dbus_socket_line_shift(DBusSocket *socket) {
        size_t n_unused;
        char *p;

        n_unused = socket->in.data_size - socket->in.data_end;
        if (_c_likely_(n_unused))
                return 0;

        if (socket->in.data_start) {
                memmove(socket->in.data,
                        socket->in.data + socket->in.data_start,
                        socket->in.data_end - socket->in.data_start);
        } else {
                if (socket->in.data_size >= DBUS_SOCKET_LINE_MAX)
                        return -EMSGSIZE;

                p = malloc(DBUS_SOCKET_LINE_MAX);
                if (!p)
                        return -ENOMEM;

                memcpy(p,
                       socket->in.data + socket->in.data_start,
                       socket->in.data_end - socket->in.data_start);

                free(socket->in.data);
                socket->in.data = p;
                socket->in.data_size = DBUS_SOCKET_LINE_MAX;
        }

        socket->in.data_end -= socket->in.data_start;
        socket->in.data_pos -= socket->in.data_start;
        socket->in.data_start = 0;

        return 0;
}

/**
 * dbus_socket_read_line() - XXX
 */
int dbus_socket_read_line(DBusSocket *socket, char **linep, size_t *np) {
        int r;

        assert(!socket->in.lines_done);

        r = dbus_socket_line_pop(socket, linep, np);
        if (r != -EAGAIN)
                return r;

        r = dbus_socket_line_shift(socket);
        if (r < 0)
                return r;

        assert(!socket->in.n_fds);
        r = dbus_socket_recvmsg(socket->fd,
                                socket->in.data,
                                &socket->in.data_end,
                                &socket->in.data_size,
                                &socket->in.fds,
                                &socket->in.n_fds);
        if (r < 0)
                return r;

        return dbus_socket_line_pop(socket, linep, np);
}

static int dbus_socket_message_pop(DBusSocket *socket, DBusMessage **messagep) {
        DBusMessageHeader header;
        DBusMessage *msg;
        size_t n, n_data;
        int r;

        msg = socket->in.pending_message;
        n_data = socket->in.data_end - socket->in.data_start;

        if (!msg) {
                n = sizeof(DBusMessageHeader);
                if (n_data < n)
                        return -EAGAIN;

                memcpy(&header, socket->in.data + socket->in.data_start, n);

                r = dbus_message_new(&msg, header);
                if (r < 0)
                        return r;

                n_data -= n;
                socket->in.data_start += n;
                socket->in.data_pos += n;
                socket->in.pending_message = msg;
        }

        if (n_data > 0) {
                n = c_min(n_data, msg->n_data - msg->n_copied);
                memcpy(msg->data + msg->n_copied, socket->in.data + socket->in.data_start, n);

                n_data -= n;
                socket->in.data_start += n;
                socket->in.data_pos += n;
                msg->n_copied += n;
        }

        if (!n_data && _c_unlikely_(socket->in.n_fds)) {
                if (msg->n_fds)
                        return -EBADMSG;

                msg->fds = socket->in.fds;
                msg->n_fds = socket->in.n_fds;
                socket->in.fds = NULL;
                socket->in.n_fds = 0;
        }

        if (msg->n_copied < msg->n_data)
                return -EAGAIN;

        *messagep = msg;
        socket->in.pending_message = NULL;
        return 0;
}

static int dbus_socket_message_shift(DBusSocket *socket) {
        memmove(socket->in.data,
                socket->in.data + socket->in.data_start,
                socket->in.data_end - socket->in.data_start);
        socket->in.data_end -= socket->in.data_start;
        socket->in.data_pos -= socket->in.data_start;
        socket->in.data_start = 0;
        return 0;
}

/**
 * dbus_socket_read_message() - XXX
 */
int dbus_socket_read_message(DBusSocket *socket, DBusMessage **messagep) {
        DBusMessage *msg;
        int r;

        if (_c_unlikely_(!socket->in.lines_done)) {
                socket->in.lines_done = true;
        }

        r = dbus_socket_message_pop(socket, messagep);
        if (r != -EAGAIN)
                return r;

        r = dbus_socket_message_shift(socket);
        if (r < 0)
                return r;

        msg = socket->in.pending_message;
        if (msg && msg->n_data - msg->n_copied >= socket->in.data_size - socket->in.data_end) {
                r = dbus_socket_recvmsg(socket->fd,
                                        msg->data,
                                        &msg->n_copied,
                                        &msg->n_data,
                                        &msg->fds,
                                        &msg->n_fds);
                if (r < 0)
                        return r;
        } else {
                r = dbus_socket_recvmsg(socket->fd,
                                        socket->in.data,
                                        &socket->in.data_end,
                                        &socket->in.data_size,
                                        &socket->in.fds,
                                        &socket->in.n_fds);
                if (r < 0)
                        return r;
        }

        return dbus_socket_message_pop(socket, messagep);
}

int dbus_socket_reserve_line(DBusSocket *socket,
                             size_t n_bytes,
                             char **linep,
                             size_t **posp) {
        DBusSocketLineBuffer *buffer;
        int r;

        assert(!socket->out.lines_done);

        buffer = c_list_last_entry(&socket->out.lines,
                                   DBusSocketLineBuffer,
                                   link);

        if (!buffer || buffer->data_size - buffer->data_pos < n_bytes) {
                r = dbus_socket_line_buffer_new(&buffer, socket, n_bytes);
                if (r < 0)
                        return r;
        }

        *linep = buffer->data + buffer->data_pos;
        *posp = &buffer->data_pos;
        return 0;
}

int dbus_socket_queue_message(DBusSocket *socket, DBusMessage *message) {
        DBusSocketMessageEntry *entry;

        if (_c_unlikely_(!socket->out.lines_done)) {
                socket->out.lines_done = true;
        }

        entry = calloc(1, sizeof(*entry));
        if (!entry)
                return 0;

        entry->message = dbus_message_ref(message);
        c_list_link_tail(&socket->out.messages, &entry->link);

        return 0;
}
