/*
 * D-Bus Socket Abstraction
 *
 * The Socket objects wraps a single connection between two DBus peers
 * using streaming sockets. File-desciptor management is done by the caller.
 * This object is mainly used for line and message buffering. It supports
 * dual-mode: Line-based buffers for initial SASL transactions, and
 * message-based buffers for DBus transactions.
 *
 * The first line (if any) of a SASL exchange sent from a client to a server
 * must be prepended with a null byte, which the caller must take care of.
 *
 * Note that once the first real DBus message was read, you must not use the
 * line-helpers, anymore!
 */

#include <c-list.h>
#include <c-macro.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include "dbus/message.h"
#include "dbus/socket.h"
#include "util/error.h"
#include "util/fdlist.h"
#include "util/user.h"

static char *socket_buffer_get_base(SocketBuffer *buffer) {
        return (char *)(buffer->vecs + buffer->n_vecs);
}

static int socket_buffer_new_internal(SocketBuffer **bufferp, size_t n_vecs, size_t n_line) {
        SocketBuffer *buffer;

        buffer = malloc(sizeof(*buffer) + n_vecs * sizeof(*buffer->vecs) + n_line);
        if (!buffer)
                return error_origin(-ENOMEM);

        buffer->link = (CList)C_LIST_INIT(buffer->link);
        user_charge_init(&buffer->charges[0]);
        user_charge_init(&buffer->charges[1]);
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

        r = socket_buffer_new_internal(&buffer, 1, c_max(n, SOCKET_LINE_PREALLOC));
        if (r)
                return error_trace(r);

        buffer->vecs[0] = (struct iovec){ socket_buffer_get_base(buffer), 0 };

        *bufferp = buffer;
        return 0;
}

int socket_buffer_new(SocketBuffer **bufferp, Message *message) {
        SocketBuffer *buffer;
        int r;

        r = socket_buffer_new_internal(&buffer, C_ARRAY_SIZE(message->vecs), 0);
        if (r)
                return error_trace(r);

        buffer->message = message_ref(message);
        memcpy(buffer->vecs, message->vecs, sizeof(message->vecs));

        *bufferp = buffer;
        return 0;
}

SocketBuffer *socket_buffer_free(SocketBuffer *buffer) {
        if (!buffer)
                return NULL;

        user_charge_deinit(&buffer->charges[1]);
        user_charge_deinit(&buffer->charges[0]);
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

static void socket_discard_input(Socket *socket) {
        if (socket->lines_done)
                socket->in.pending_message = message_unref(socket->in.pending_message);
        else
                socket->in.line_cursor = socket->in.data_end;
        socket->in.fds = fdlist_free(socket->in.fds);
}

static void socket_discard_output(Socket *socket) {
        SocketBuffer *buffer;

        while ((buffer = c_list_first_entry(&socket->out.queue, SocketBuffer, link)))
                socket_buffer_free(buffer);
}

/**
 * socket_init() - XXX
 */
int socket_init(Socket *socket, User *user, int fd) {
        *socket = (Socket){};
        socket->user = user_ref(user);
        socket->fd = fd;
        socket->in.data_size = SOCKET_DATA_RECV_MAX;
        socket->out.queue = (CList)C_LIST_INIT(socket->out.queue);

        socket->in.data = malloc(socket->in.data_size);
        if (!socket->in.data)
                return error_origin(-ENOMEM);

        return 0;
}

/**
 * socket_deinit() - XXX
 */
void socket_deinit(Socket *socket) {
        socket_discard_input(socket);
        socket_discard_output(socket);

        assert(c_list_is_empty(&socket->out.queue));
        assert(!socket->in.fds);
        if (socket->lines_done)
                assert(!socket->in.pending_message);

        socket->in.data = c_free(socket->in.data);
        socket->fd = -1;
        socket->user = user_unref(socket->user);
}

static void socket_hangup_input(Socket *socket) {
        /*
         * A read-side hangup is detected when recv(2) returns EOF or failure.
         * In that case, we stop reading data from the socket, but still
         * dispatch all pending input. Hence, we don't discard input buffers.
         */
        socket->hup_in = true;
}

static void socket_hangup_output(Socket *socket) {
        /*
         * A write-side hangup is detected when send(2) or recv(2) fail. In
         * that case, we cannot ever continue writing data to the socket, even
         * though there might still be data to read.
         * We always discard our output buffers, since the remote peer
         * disconnected asynchronously, and there is no way for us to avoid
         * data loss.
         */
        socket->hup_out = true;
        socket_discard_output(socket);
}

/**
 * socket_dequeue_line() - XXX
 */
int socket_dequeue_line(Socket *socket, const char **linep, size_t *np) {
        char *line;
        size_t n;

        assert(!socket->lines_done);

        /*
         * Advance our cursor byte by byte and look for an end-of-line. We
         * remember the parser position, so no byte is ever parsed twice.
         */
        for ( ; socket->in.line_cursor < socket->in.data_end; ++socket->in.line_cursor) {
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
                if (_c_unlikely_(socket->in.line_cursor + 1 == socket->in.data_end && socket->in.fds))
                        socket->in.fds = fdlist_free(socket->in.fds);

                /*
                 * If we find an \r\n, advance the start indicator and return
                 * a pointer to the caller so they can parse the line.
                 * We do NOT copy the line. We leave it in the buffer untouched
                 * and return a direct pointer into the buffer. The pointer is
                 * only valid until the next call into this Socket object.
                 */
                if (socket->in.line_cursor > 0 &&
                    socket->in.data[socket->in.line_cursor] == '\n' &&
                    socket->in.data[socket->in.line_cursor - 1] == '\r') {
                        /* remember start and length without \r\n */
                        line = socket->in.data + socket->in.data_start;
                        n = socket->in.line_cursor - socket->in.data_start - 1;

                        /* forward iterator */
                        socket->in.data_start = ++socket->in.line_cursor;

                        /* replace \r by safety NUL and return to caller */
                        line[n] = 0;
                        *linep = (const char *)line;
                        *np = n;
                        return 0;
                }
        }

        if (_c_unlikely_(socket->hup_in)) {
                if (socket->hup_out)
                        return SOCKET_E_RESET;
                else
                        return SOCKET_E_EOF;
        }

        *linep = NULL;
        *np = 0;
        return 0;
}

/**
 * socket_dequeue() - XXX
 */
int socket_dequeue(Socket *socket, Message **messagep) {
        MessageHeader header;
        Message *msg;
        size_t n, n_data;
        int r;

        if (_c_unlikely_(!socket->lines_done)) {
                assert(socket->in.line_cursor == socket->in.data_start);
                socket->lines_done = true;
                socket->in.pending_message = NULL;
        }

        msg = socket->in.pending_message;
        n_data = socket->in.data_end - socket->in.data_start;

        if (!msg) {
                n = sizeof(MessageHeader);
                if (_c_unlikely_(n_data < n)) {
                        *messagep = NULL;

                        if (_c_unlikely_(socket->hup_in)) {
                                if (socket->hup_out)
                                        return SOCKET_E_RESET;
                                else
                                        return SOCKET_E_EOF;
                        }

                        return 0;
                }

                memcpy(&header, socket->in.data + socket->in.data_start, n);

                r = message_new_incoming(&msg, header);
                if (r == MESSAGE_E_CORRUPT_HEADER ||
                    r == MESSAGE_E_TOO_LARGE) {
                        socket_close(socket);
                        return SOCKET_E_RESET;
                } else if (r) {
                        return error_fold(r);
                }

                n_data -= n;
                socket->in.data_start += n;
                socket->in.pending_message = msg;
        }

        if (n_data > 0) {
                n = c_min(n_data, msg->n_data - msg->n_copied);
                memcpy(msg->data + msg->n_copied, socket->in.data + socket->in.data_start, n);

                n_data -= n;
                socket->in.data_start += n;
                msg->n_copied += n;
        }

        if (_c_unlikely_(!n_data && socket->in.fds)) {
                if (msg->fds) {
                        socket_close(socket);
                        return SOCKET_E_RESET;
                }

                msg->fds = socket->in.fds;
                socket->in.fds = NULL;
        }

        if (msg->n_copied >= msg->n_data) {
                *messagep = msg;
                socket->in.pending_message = NULL;
                return 0;
        }

        if (_c_unlikely_(socket->hup_in)) {
                if (socket->hup_out)
                        return SOCKET_E_RESET;
                else
                        return SOCKET_E_EOF;
        }

        *messagep = NULL;
        return 0;
}

/**
 * socket_queue_line() - XXX
 */
int socket_queue_line(Socket *socket, User *user, const char *line_in, size_t n) {
        SocketBuffer *buffer;
        char *line_out;
        size_t *pos;
        int r;

        assert(!socket->lines_done);

        if (_c_unlikely_(socket->hup_out || socket->shutdown))
                return 0;

        buffer = c_list_last_entry(&socket->out.queue, SocketBuffer, link);
        if (!buffer || n + strlen("\r\n") > socket_buffer_get_line_space(buffer)) {
                r = socket_buffer_new_line(&buffer, n + strlen("\r\n"));
                if (r)
                        return error_trace(r);

                r = user_charge(socket->user, &buffer->charges[0], user, USER_SLOT_BYTES, n + strlen("\r\n"));
                if (r) {
                        socket_buffer_free(buffer);

                        if (r == USER_E_QUOTA)
                                return SOCKET_E_QUOTA;
                        else
                                return error_fold(r);
                }

                c_list_link_tail(&socket->out.queue, &buffer->link);
        }

        r = user_charge(socket->user, &buffer->charges[0], user, USER_SLOT_BYTES, n + strlen("\r\n"));
        if (r) {
                if (r == USER_E_QUOTA)
                        return SOCKET_E_QUOTA;
                else
                        return error_fold(r);
        }

        socket_buffer_get_line_cursor(buffer, &line_out, &pos);

        memcpy(line_out, line_in, n);
        line_out += n;
        *pos += n;

        memcpy(line_out, "\r\n", strlen("\r\n"));
        *pos += strlen("\r\n");

        return 0;
}

/**
 * socket_queue() - XXX
 */
int socket_queue(Socket *socket, User *user, SocketBuffer *buffer) {
        int r;

        assert(buffer->message);
        assert(!c_list_is_linked(&buffer->link));

        r = user_charge(socket->user, &buffer->charges[0], user, USER_SLOT_BYTES, buffer->message->n_data);
        r = r ?: user_charge(socket->user, &buffer->charges[1], user, USER_SLOT_FDS, fdlist_count(buffer->message->fds));
        if (r) {
                if (r == USER_E_QUOTA)
                        return SOCKET_E_QUOTA;
                else
                        return error_fold(r);
        }

        if (_c_unlikely_(!socket->lines_done)) {
                assert(socket->in.line_cursor == socket->in.data_start);
                socket->lines_done = true;
                socket->in.pending_message = NULL;
        }

        if (_c_unlikely_(socket->hup_out || socket->shutdown))
                socket_buffer_free(buffer);
        else
                c_list_link_tail(&socket->out.queue, &buffer->link);

        return 0;
}

static int socket_recvmsg(Socket *socket, void *buffer, size_t n_buffer, size_t *from, size_t *to, FDList **fdsp) {
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
        assert(n_buffer <= *to);

        msg = (struct msghdr){
                .msg_iov = &(struct iovec){
                        .iov_base = buffer + *from,
                        .iov_len = c_min(*to - *from, n_buffer),
                },
                .msg_iovlen = 1,
                .msg_control = &control,
                .msg_controllen = sizeof(control),
        };

        l = recvmsg(socket->fd, &msg, MSG_DONTWAIT | MSG_CMSG_CLOEXEC);
        if (_c_unlikely_(!l)) {
                socket_hangup_input(socket);
                return SOCKET_E_LOST_INTEREST;
        } else if (_c_unlikely_(l < 0)) {
                switch (errno) {
                case EAGAIN:
                        return 0;
                case ECOMM:
                case ECONNABORTED:
                case ECONNRESET:
                case EHOSTDOWN:
                case EHOSTUNREACH:
                case EIO:
                case ENOBUFS:
                case ENOMEM:
                case EPIPE:
                case EPROTO:
                case EREMOTEIO:
                case ESHUTDOWN:
                case ETIMEDOUT:
                        socket_hangup_input(socket);
                        /* sendmmsg() is guaranteed to also fail, so hang up output too */
                        socket_hangup_output(socket);
                        return SOCKET_E_LOST_INTEREST;
                }

                return error_origin(-errno);
        }

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
                        socket_close(socket);
                        r = SOCKET_E_LOST_INTEREST;
                        goto error;
                }

                r = fdlist_new_consume_fds(fdsp, fds, n_fds);
                if (r) {
                        r = error_fold(r);
                        goto error;
                }
        }

        *from += l;
        return SOCKET_E_PREEMPTED;

error:
        while (n_fds)
                close(fds[--n_fds]);
        return r;
}

static int socket_dispatch_read(Socket *socket) {
        void *p;

        if (_c_unlikely_(socket_has_input(socket)))
                return 0;

        /*
         * Always shift the input buffer. In case of the line-parser this
         * should never happen in normal operation: the only way to leave
         * behinda partial line is by filling the whole buffer, in that case
         * at most SOCKET_DATA_RECV_MAX bytes need to be moved. And for the
         * message-parser, there can be at most one message header left
         * behind (16 bytes).
         */
        memmove(socket->in.data,
                socket->in.data + socket->in.data_start,
                socket->in.data_end - socket->in.data_start);
        if (_c_unlikely_(!socket->lines_done))
                socket->in.line_cursor -= socket->in.data_start;
        socket->in.data_end -= socket->in.data_start;
        socket->in.data_start = 0;

        if (_c_unlikely_(socket->in.data_size <= socket->in.data_end)) {
                /*
                 * In case our input buffer is full, we need to resize it. This can
                 * only happen for the line-reader, since messages leave as most 16
                 * bytes behind (size of a single header).
                 * The line-reader, however, parses the entire line into the input
                 * buffer. Hence, in case the normal buffer size is exceeded, we
                 * re-allocate once to the maximum.
                 */
                assert(!socket->lines_done);

                if (socket->in.data_size >= SOCKET_LINE_MAX) {
                        socket_close(socket);
                        return SOCKET_E_LOST_INTEREST;
                }

                p = malloc(SOCKET_LINE_MAX);
                if (!p)
                        return error_origin(-ENOMEM);

                memcpy(p,
                       socket->in.data + socket->in.data_start,
                       socket->in.data_end - socket->in.data_start);

                free(socket->in.data);
                socket->in.data = p;
                socket->in.data_size = SOCKET_LINE_MAX;
                socket->in.data_end -= socket->in.data_start;
                socket->in.line_cursor -= socket->in.data_start;
                socket->in.data_start = 0;
        } else if (_c_likely_(socket->lines_done)) {
                Message *msg = socket->in.pending_message;

                if (_c_unlikely_(msg && msg->n_data - msg->n_copied >= socket->in.data_size - socket->in.data_end)) {
                        /*
                         * If there is a pending message, we try to shortcut the input buffer
                         * for overlong payloads. This avoids copying the message twice, at the
                         * cost of being unable to receive multiple messages at once. Hence, if
                         * messages are small, we prefer the round via the input buffer so we
                         * reduce the number of calls into the kernel.
                         */
                        return socket_recvmsg(socket,
                                              msg->data,
                                              msg->n_data,
                                              &msg->n_copied,
                                              &msg->n_data,
                                              &msg->fds);
                }
        }

        /*
         * Read more data into the input buffer, and store the file-descriptors
         * in the buffer as well.
         *
         * Note that the kernel always breaks recvmsg() calls after an SKB with
         * file-descriptor payload. Hence, this could be improvded with
         * recvmmsg() so we get multiple messages at all cost. However, FD
         * passing is no fast-path and should never be, so there is little
         * reason to resort to recvmmsg() (which would be non-trivial, anyway,
         * since we would need multiple input buffers).
         */
        return socket_recvmsg(socket,
                              socket->in.data,
                              SOCKET_DATA_RECV_MAX,
                              &socket->in.data_end,
                              &socket->in.data_size,
                              &socket->in.fds);
}

static int socket_dispatch_write(Socket *socket) {
        SocketBuffer *buffer, *safe;
        struct mmsghdr msgs[SOCKET_MMSG_MAX];
        struct msghdr *msg;
        int r, i, n_msgs;

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

                if (++n_msgs >= (ssize_t)C_ARRAY_SIZE(msgs))
                        break;
        }

        if (!n_msgs)
                return SOCKET_E_LOST_INTEREST;

        n_msgs = sendmmsg(socket->fd, msgs, n_msgs, MSG_DONTWAIT | MSG_NOSIGNAL);
        if (n_msgs < 0) {
                switch (errno) {
                case EAGAIN:
                        return 0;
                case ECOMM:
                case ECONNABORTED:
                case ECONNRESET:
                case EHOSTDOWN:
                case EHOSTUNREACH:
                case EIO:
                case ENOBUFS:
                case ENOMEM:
                case EPIPE:
                case EPROTO:
                case EREMOTEIO:
                case ESHUTDOWN:
                case ETIMEDOUT:
                        socket_hangup_output(socket);
                        return SOCKET_E_LOST_INTEREST;
                }

                return error_origin(-errno);
        }

        i = 0;
        c_list_for_each_entry_safe(buffer, safe, &socket->out.queue, link) {
                if (i >= n_msgs)
                        break;

                if (socket_buffer_consume(buffer, msgs[i].msg_len))
                        socket_buffer_free(buffer);

                ++i;
        }
        assert(i == n_msgs);

        if (c_list_is_empty(&socket->out.queue)) {
                if (_c_unlikely_(socket->shutdown)) {
                        r = shutdown(socket->fd, SHUT_WR);
                        assert(r >= 0);

                        socket_hangup_output(socket);
                }

                return SOCKET_E_LOST_INTEREST;
        }

        return 0;
}

/**
 * socket_dispatch() - XXX
 */
int socket_dispatch(Socket *socket, uint32_t event) {
        int r = SOCKET_E_LOST_INTEREST;

        switch (event) {
        case EPOLLIN:
                if (!socket->hup_in) {
                        r = socket_dispatch_read(socket);
                        if (r < 0)
                                return r;
                }
                break;
        case EPOLLOUT:
                if (!socket->hup_out) {
                        r = socket_dispatch_write(socket);
                        if (r < 0)
                                return r;
                }
                break;
        case EPOLLHUP:
                socket_hangup_output(socket);
                r = SOCKET_E_PREEMPTED;
                break;
        }

        return r;
}

/**
 * socket_shutdown() - disallow further queueing on the socket
 *
 * This dissalows further queuing on the socket, but still flushes out the
 * pending socket buffers to the kernel. Once all pending output has been
 * sent the remote end is notified of the shutdown.
 */
void socket_shutdown(Socket *socket) {
        int r;

        socket->shutdown = true;

        if (!socket_has_output(socket)) {
                r = shutdown(socket->fd, SHUT_WR);
                assert(r >= 0);

                socket_hangup_output(socket);
        }
}

/**
 * socket_close() - close both communication directions
 * @socket:                     socket to operate on
 *
 * This dissalows both further queuing and dequeuing on the socket, but
 * still flushes out the pending socket buffers to the kernel. Once all
 * pending output has been sent the remote end is notifiode of the shutdown.
 */
void socket_close(Socket *socket) {
        socket_shutdown(socket);
        socket_hangup_input(socket);
        socket_discard_input(socket);
}
