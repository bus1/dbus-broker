/*
 * D-Bus Socket Abstraction
 *
 * The Socket objects wraps a single connection between two DBus peers
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
#include "message.h"
#include "socket.h"
#include "util/fdlist.h"

static char *socket_buffer_get_base(SocketBuffer *buffer) {
        return (char *)(buffer->vecs + buffer->n_vecs);
}

static int socket_buffer_new(SocketBuffer **bufferp, size_t n_vecs, size_t n_line) {
        SocketBuffer *buffer;

        buffer = malloc(sizeof(*buffer) + n_vecs * sizeof(*buffer->vecs) + n_line);
        if (!buffer)
                return -ENOMEM;

        buffer->link = (CList)C_LIST_INIT(buffer->link);
        buffer->n_total = n_line;
        buffer->message = NULL;
        buffer->n_vecs = n_vecs;
        buffer->writer = NULL;

        *bufferp = buffer;
        return 0;
}

static int socket_buffer_new_line(SocketBuffer **bufferp, size_t n) {
        SocketBuffer *buffer;
        int r;

        r = socket_buffer_new(&buffer, 1, c_max(n, SOCKET_LINE_PREALLOC));
        if (r)
                return r;

        buffer->vecs[0] = (struct iovec){ socket_buffer_get_base(buffer), 0 };

        *bufferp = buffer;
        return 0;
}

int socket_buffer_new_message(SocketBuffer **bufferp, Message *message) {
        SocketBuffer *buffer;
        int r;

        r = socket_buffer_new(&buffer, C_ARRAY_SIZE(message->vecs), 0);
        if (r)
                return r;

        buffer->message = message_ref(message);
        memcpy(buffer->vecs, message->vecs, sizeof(message->vecs));

        *bufferp = buffer;
        return 0;
}

SocketBuffer *socket_buffer_free(SocketBuffer *buffer) {
        if (!buffer)
                return NULL;

        c_list_unlink_init(&buffer->link);
        message_unref(buffer->message);
        free(buffer);

        return NULL;
}

static size_t socket_buffer_get_line_space(SocketBuffer *buffer) {
        size_t n_remaining;

        assert(!buffer->message);

        n_remaining = buffer->n_total;
        n_remaining -= (char *)buffer->vecs[0].iov_base - socket_buffer_get_base(buffer);
        n_remaining -= buffer->vecs[0].iov_len;

        return n_remaining;
}

static void socket_buffer_get_line_cursor(SocketBuffer *buffer, char **datap, size_t **posp) {
        assert(!buffer->message);

        *datap = buffer->vecs[0].iov_base + buffer->vecs[0].iov_len;
        *posp = &buffer->vecs[0].iov_len;
}

static bool socket_buffer_is_uncomsumed(SocketBuffer *buffer) {
        return !buffer->writer;
}

static bool socket_buffer_is_consumed(SocketBuffer *buffer) {
        return buffer->writer >= buffer->vecs + buffer->n_vecs;
}

static bool socket_buffer_consume(SocketBuffer *buffer, size_t n) {
        size_t t;

        if (!buffer->writer)
                buffer->writer = buffer->vecs;

        for ( ; !socket_buffer_is_consumed(buffer); ++buffer->writer) {
                t = c_min(buffer->writer->iov_len, n);
                buffer->writer->iov_len -= t;
                buffer->writer->iov_base += t;
                n -= t;
                if (buffer->writer->iov_len)
                        break;
        }

        assert(!n);

        return socket_buffer_is_consumed(buffer);
}

int socket_new(Socket **socketp, int fd) {
        _c_cleanup_(socket_freep) Socket *socket = NULL;

        socket = calloc(1, sizeof(*socket));
        if (!socket)
                return -ENOMEM;

        socket->fd = fd;

        socket->out.queue = (CList)C_LIST_INIT(socket->out.queue);

        socket->in.data_size = 2048;
        socket->in.data = malloc(socket->in.data_size);
        if (!socket->in.data)
                return -ENOMEM;

        *socketp = socket;
        socket = NULL;
        return 0;
}

Socket *socket_free(Socket *socket) {
        SocketBuffer *buffer;

        if (!socket)
                return NULL;

        socket->fd = c_close(socket->fd);

        while ((buffer = c_list_first_entry(&socket->out.queue, SocketBuffer, link)))
                socket_buffer_free(buffer);

        message_unref(socket->in.pending_message);
        fdlist_free(socket->in.fds);
        free(socket->in.data);
        free(socket);

        return NULL;
}

static int socket_recvmsg(int fd, void *buffer, size_t *from, size_t *to, FDList **fdsp) {
        union {
                struct cmsghdr cmsg;
                char buffer[CMSG_SPACE(sizeof(int) * SOCKET_FD_MAX)];
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
                        assert(n_fds <= SOCKET_FD_MAX);
                } else {
                        /* XXX: debug message? */
                }
        }

        if (_c_unlikely_(n_fds)) {
                if (_c_unlikely_(*fdsp)) {
                        r = -EBADMSG;
                        goto error;
                }

                r = fdlist_new_consume_fds(fdsp, fds, n_fds);
                if (r)
                        goto error;
        }

        *from += l;
        return 0;

error:
        while (n_fds)
                close(fds[--n_fds]);
        return r;
}

static int socket_line_pop(Socket *socket, char **linep, size_t *np) {
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
                if (_c_unlikely_(socket->in.data_pos + 1 == socket->in.data_end && socket->in.fds))
                        socket->in.fds = fdlist_free(socket->in.fds);

                /*
                 * If we find an \r\n, advance the start indicator and return
                 * a pointer to the caller so they can parse the line.
                 * We do NOT copy the line. We leave it in the buffer untouched
                 * and return a direct pointer into the buffer. The pointer is
                 * only valid until the next call into this Socket object.
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

static int socket_line_shift(Socket *socket) {
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
                if (socket->in.data_size >= SOCKET_LINE_MAX)
                        return -EMSGSIZE;

                p = malloc(SOCKET_LINE_MAX);
                if (!p)
                        return -ENOMEM;

                memcpy(p,
                       socket->in.data + socket->in.data_start,
                       socket->in.data_end - socket->in.data_start);

                free(socket->in.data);
                socket->in.data = p;
                socket->in.data_size = SOCKET_LINE_MAX;
        }

        socket->in.data_end -= socket->in.data_start;
        socket->in.data_pos -= socket->in.data_start;
        socket->in.data_start = 0;

        return 0;
}

/**
 * socket_read_line() - XXX
 */
int socket_read_line(Socket *socket, char **linep, size_t *np) {
        int r;

        assert(!socket->lines_done);

        r = socket_line_pop(socket, linep, np);
        if (r != -EAGAIN)
                return r;

        r = socket_line_shift(socket);
        if (r < 0)
                return r;

        assert(!socket->in.fds);
        r = socket_recvmsg(socket->fd,
                           socket->in.data,
                           &socket->in.data_end,
                           &socket->in.data_size,
                           &socket->in.fds);
        if (r < 0)
                return r;

        return socket_line_pop(socket, linep, np);
}

static int socket_message_pop(Socket *socket, Message **messagep) {
        MessageHeader header;
        Message *msg;
        size_t n, n_data;
        int r;

        msg = socket->in.pending_message;
        n_data = socket->in.data_end - socket->in.data_start;

        if (!msg) {
                n = sizeof(MessageHeader);
                if (n_data < n)
                        return -EAGAIN;

                memcpy(&header, socket->in.data + socket->in.data_start, n);

                r = message_new_incoming(&msg, header);
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

        if (_c_unlikely_(!n_data && socket->in.fds)) {
                if (msg->fds)
                        return -EBADMSG;

                msg->fds = socket->in.fds;
                socket->in.fds = NULL;
        }

        if (msg->n_copied < msg->n_data)
                return -EAGAIN;

        *messagep = msg;
        socket->in.pending_message = NULL;
        return 0;
}

static int socket_message_shift(Socket *socket) {
        memmove(socket->in.data,
                socket->in.data + socket->in.data_start,
                socket->in.data_end - socket->in.data_start);
        socket->in.data_end -= socket->in.data_start;
        socket->in.data_pos -= socket->in.data_start;
        socket->in.data_start = 0;
        return 0;
}

/**
 * socket_read_message() - XXX
 */
int socket_read_message(Socket *socket, Message **messagep) {
        Message *msg;
        int r;

        if (_c_unlikely_(!socket->lines_done)) {
                socket->lines_done = true;
        }

        r = socket_message_pop(socket, messagep);
        if (r != -EAGAIN)
                return r;

        r = socket_message_shift(socket);
        if (r < 0)
                return r;

        msg = socket->in.pending_message;
        if (msg && msg->n_data - msg->n_copied >= socket->in.data_size - socket->in.data_end) {
                r = socket_recvmsg(socket->fd,
                                   msg->data,
                                   &msg->n_copied,
                                   &msg->n_data,
                                   &msg->fds);
                if (r < 0)
                        return r;
        } else {
                r = socket_recvmsg(socket->fd,
                                   socket->in.data,
                                   &socket->in.data_end,
                                   &socket->in.data_size,
                                   &socket->in.fds);
                if (r < 0)
                        return r;
        }

        return socket_message_pop(socket, messagep);
}

/**
 * socket_queue_line() - XXX
 */
int socket_queue_line(Socket *socket, size_t n_bytes, char **linep, size_t **posp) {
        SocketBuffer *buffer;
        int r;

        assert(!socket->lines_done);

        buffer = c_list_last_entry(&socket->out.queue, SocketBuffer, link);
        if (!buffer || n_bytes > socket_buffer_get_line_space(buffer)) {
                r = socket_buffer_new_line(&buffer, n_bytes);
                if (r)
                        return r;

                c_list_link_tail(&socket->out.queue, &buffer->link);
        }

        socket_buffer_get_line_cursor(buffer, linep, posp);
        return 0;
}

/**
 * socket_queue_message() - XXX
 */
int socket_queue_message(Socket *socket, Message *message) {
        SocketBuffer *buffer;
        int r;

        if (_c_unlikely_(!socket->lines_done))
                socket->lines_done = true;

        r = socket_buffer_new_message(&buffer, message);
        if (!r)
                c_list_link_tail(&socket->out.queue, &buffer->link);

        return r;
}

/**
 * socket_write() - XXX
 */
int socket_write(Socket *socket) {
        SocketBuffer *buffer, *safe;
        struct mmsghdr msgs[SOCKET_MMSG_MAX];
        struct msghdr *msg;
        int i, n_msgs;

        n_msgs = 0;
        c_list_for_each_entry(buffer, &socket->out.queue, link) {
                msg = &msgs[n_msgs].msg_hdr;

                msg->msg_name = NULL;
                msg->msg_namelen = 0;
                msg->msg_iov = buffer->vecs;
                msg->msg_iovlen = buffer->n_vecs;
                if (buffer->message &&
                    buffer->message->fds &&
                    socket_buffer_is_uncomsumed(buffer)) {
                        msg->msg_control = buffer->message->fds->cmsg;
                        msg->msg_controllen = buffer->message->fds->cmsg->cmsg_len;
                } else {
                        msg->msg_control = NULL;
                        msg->msg_controllen = 0;
                }
                msg->msg_flags = 0;

                if (++n_msgs >= C_ARRAY_SIZE(msgs))
                        break;
        }

        if (!n_msgs)
                return 0;

        n_msgs = sendmmsg(socket->fd, msgs, n_msgs, MSG_DONTWAIT | MSG_NOSIGNAL);
        if (n_msgs < 0)
                return -errno;

        i = 0;
        c_list_for_each_entry_safe(buffer, safe, &socket->out.queue, link) {
                if (i >= n_msgs)
                        break;

                if (socket_buffer_consume(buffer, msgs[i].msg_len))
                        socket_buffer_free(buffer);

                ++i;
        }
        assert(i == n_msgs);

        return !c_list_is_empty(&socket->out.queue);
}
