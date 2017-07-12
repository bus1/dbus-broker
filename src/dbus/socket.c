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
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include "dbus/message.h"
#include "dbus/socket.h"
#include "util/error.h"
#include "util/fdlist.h"
#include "util/user.h"

struct SocketBuffer {
        CList link;
        UserCharge charges[2];

        size_t n_total;
        Message *message;

        size_t n_vecs;
        struct iovec *writer;
        struct iovec vecs[];
};

static char *socket_buffer_get_base(SocketBuffer *buffer) {
        return (char *)(buffer->vecs + buffer->n_vecs);
}

static SocketBuffer *socket_buffer_free(SocketBuffer *buffer) {
        if (!buffer)
                return NULL;

        user_charge_deinit(&buffer->charges[1]);
        user_charge_deinit(&buffer->charges[0]);
        c_list_unlink_init(&buffer->link);
        message_unref(buffer->message);
        free(buffer);

        return NULL;
}

C_DEFINE_CLEANUP(SocketBuffer *, socket_buffer_free);

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

static int socket_buffer_new_line(SocketBuffer **bufferp,
                                  Socket *socket,
                                  User *user,
                                  size_t n) {
        _c_cleanup_(socket_buffer_freep) SocketBuffer *buffer = NULL;
        int r;

        r = socket_buffer_new_internal(&buffer, 1, c_max(n, SOCKET_LINE_PREALLOC));
        if (r)
                return error_trace(r);

        buffer->vecs[0] = (struct iovec){ socket_buffer_get_base(buffer), 0 };

        r = user_charge(socket->user,
                        &buffer->charges[0],
                        user,
                        USER_SLOT_BYTES,
                        sizeof(SocketBuffer) + buffer->n_total);
        if (r)
                return (r == USER_E_QUOTA) ? SOCKET_E_QUOTA : error_fold(r);

        *bufferp = buffer;
        buffer = NULL;
        return 0;
}

static int socket_buffer_new_message(SocketBuffer **bufferp,
                                     Socket *socket,
                                     User *user,
                                     Message *message) {
        _c_cleanup_(socket_buffer_freep) SocketBuffer *buffer = NULL;
        int r;

        r = socket_buffer_new_internal(&buffer, C_ARRAY_SIZE(message->vecs), 0);
        if (r)
                return error_trace(r);

        buffer->message = message_ref(message);
        memcpy(buffer->vecs, message->vecs, sizeof(message->vecs));

        r = user_charge(socket->user,
                        &buffer->charges[0],
                        user,
                        USER_SLOT_BYTES,
                        sizeof(SocketBuffer) + sizeof(Message) + message->n_data);
        if (r)
                return (r == USER_E_QUOTA) ? SOCKET_E_QUOTA : error_fold(r);

        r = user_charge(socket->user,
                        &buffer->charges[1],
                        user,
                        USER_SLOT_FDS,
                        fdlist_count(buffer->message->fds));
        if (r)
                return (r == USER_E_QUOTA) ? SOCKET_E_QUOTA : error_fold(r);

        *bufferp = buffer;
        buffer = NULL;
        return 0;
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
        socket->in.pending_message = message_unref(socket->in.pending_message);
        socket->in.data_start = socket->in.data_end;
        socket->in.cursor = socket->in.data_end;
        socket->in.fds = fdlist_free(socket->in.fds);

        user_charge_deinit(&socket->in.charge_msg_fds);
        user_charge_deinit(&socket->in.charge_msg_data);
        user_charge_deinit(&socket->in.charge_buf_fds);
}

static void socket_discard_output(Socket *socket) {
        SocketBuffer *buffer;

        while ((buffer = c_list_first_entry(&socket->out.queue, SocketBuffer, link)))
                socket_buffer_free(buffer);
}

/**
 * socket_init() - initialize socket
 * @socket:             socket to operate on
 * @user:               socket owner, or NULL
 * @fd:                 socket file descriptor
 *
 * This initializes the new socket @socket. The socket will be owned by @user
 * (and accounted on it), and @fd will be used as socket file descriptor. Not
 * that @fd is still owned by the caller and must not be closed while the
 * socket is used.
 *
 * Return: 0 on success, negative error code on failure.
 */
void socket_init(Socket *socket, User *user, int fd) {
        *socket = (Socket)SOCKET_NULL(*socket);
        socket->user = user_ref(user);
        socket->fd = fd;
        socket->in.data_size = sizeof(socket->input_buffer);
        socket->in.data = socket->input_buffer;
}

/**
 * socket_deinit() - deinitialize socket
 * @socket:             socket to operate on
 *
 * This deinitializes @socket and clears all allocated resources. The socket is
 * cleared to SOCKET_NULL afterwards. Hence, it is safe to call socket_deinit()
 * multiple times.
 *
 * Note that the socket file descriptor is *NOT* closed. It is still owned by
 * the caller!
 */
void socket_deinit(Socket *socket) {
        socket_discard_input(socket);
        socket_discard_output(socket);

        assert(c_list_is_empty(&socket->out.queue));
        assert(!socket->in.fds);
        assert(!socket->in.pending_message);

        if (socket->in.data != socket->input_buffer) {
                socket->in.data = c_free(socket->in.data);
                user_charge_deinit(&socket->in.charge_buf_data);
        }

        socket->fd = -1;
        socket->user = user_unref(socket->user);
}

static void socket_lines_done(Socket *socket) {
        /*
         * Whenever the first call to socket_queue() or socket_dequeue() is
         * made, we shut down the line parser and prepare the message parser.
         * Note that the caller must not have partial data in the line-parser
         * at this time. That is, when calling socket_dequeue_line(), you must
         * continue using the line parser until it returns a full line. Only
         * after it returned a full line, you can switch to the message parser.
         * This is usually given, since the only trigger to switch a parser can
         * be inline data. Anything else would be very weird.
         */
        if (_c_unlikely_(!socket->lines_done)) {
                assert(socket->in.cursor == socket->in.data_start);
                socket->lines_done = true;
        }
}

static void socket_might_reset(Socket *socket) {
        Message *msg = socket->in.pending_message;

        if (_c_unlikely_(!socket->reset &&
                         socket->hup_in &&
                         socket->hup_out &&
                         socket->in.cursor >= socket->in.data_end &&
                         (!msg || msg->n_copied < msg->n_data)))
                socket->reset = true;
}

static void socket_hangup_input(Socket *socket) {
        /*
         * A read-side hangup is detected when recv(2) returns EOF or failure.
         * In that case, we stop reading data from the socket, but still
         * dispatch all pending input. Hence, we don't discard input buffers.
         */
        if (!socket->hup_in) {
                socket->hup_in = true;
                socket_might_reset(socket);
        }
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
        if (!socket->hup_out) {
                socket->hup_out = true;
                socket_discard_output(socket);
                socket_might_reset(socket);
        }
}

static void socket_shutdown_now(Socket *socket) {
        int r;

        assert(socket->shutdown);

        if (!socket->hup_out) {
                r = shutdown(socket->fd, SHUT_WR);
                assert(r >= 0);

                socket_hangup_output(socket);
        }
}

/**
 * socket_dequeue_line() - fetch line from input buffer
 * @socket:             socket to operate on
 * @linep:              output argument for read line
 * @np:                 output argument for read line length
 *
 * This fetchs the next full line from the input buffer. The \r\n is stripped,
 * and the line is returned in @linep and @np. That is, @np might be 0 (in case
 * the line was empty apart from \r\n), but @linep will still point to the line
 * in that case (that is, it is non-NULL).
 *
 * If no more lines can be fetched, this returns NULL in @linep, and 0 in @np.
 *
 * Note that any fetched line is always owned by the socket. That is, @linep is
 * only valid until the next call to a socket function. It points directly into
 * the input buffer of the socket, and might be moved, overwritten, or
 * deallocated by any other socket call.
 *
 * This function must not be called once the socket has been put into
 * message-mode. That is, the line-based I/O is torn down as soon as the first
 * message is read or written.
 *
 * Return: On success, 0 is returned and @linep and @np either contain the read
 *         line, or (NULL, 0) if there is no more data to fetch.
 *         If the input-stream was closed and no more data is to be read,
 *         SOCKET_E_EOF is returned.
 *         On fatal errors, a negative error code is returned.
 */
int socket_dequeue_line(Socket *socket, const char **linep, size_t *np) {
        char *line;
        size_t n;

        assert(!socket->lines_done);

        /*
         * Advance our cursor byte by byte and look for an end-of-line. We
         * remember the parser position, so no byte is ever parsed twice.
         */
        for ( ; socket->in.cursor < socket->in.data_end; ++socket->in.cursor) {
                /*
                 * If we are at the end of the socket buffer, we must consume
                 * any possible FD array that we recveived alongside it.
                 * The kernel always breaks _after_ skbs with FDs, but not
                 * before them. Hence, FDs are attached to the LAST byte of our
                 * socket buffer, rather than the first.
                 *
                 * During line-handling, we silently ignore any received FDs,
                 * and the DBus spec clearly states that no extension shall
                 * pass FDs during authentication.
                 */
                if (_c_unlikely_(socket->in.cursor + 1 == socket->in.data_end && socket->in.fds)) {
                        socket->in.fds = fdlist_free(socket->in.fds);
                        user_charge_deinit(&socket->in.charge_buf_fds);
                }

                /*
                 * If we find an \r\n, advance the start indicator and return
                 * a pointer to the caller so they can parse the line.
                 * We do NOT copy the line. We leave it in the buffer untouched
                 * and return a direct pointer into the buffer. The pointer is
                 * only valid until the next call into this Socket object.
                 */
                if (socket->in.cursor > 0 &&
                    socket->in.data[socket->in.cursor] == '\n' &&
                    socket->in.data[socket->in.cursor - 1] == '\r') {
                        /* remember start and length without \r\n */
                        line = socket->in.data + socket->in.data_start;
                        n = socket->in.cursor - socket->in.data_start - 1;

                        /* forward iterator */
                        socket->in.data_start = ++socket->in.cursor;

                        /* replace \r by safety NUL and return to caller */
                        line[n] = 0;
                        *linep = (const char *)line;
                        *np = n;
                        return 0;
                }
        }

        socket_might_reset(socket);
        if (_c_unlikely_(socket->hup_in))
                return SOCKET_E_EOF;

        *linep = NULL;
        *np = 0;
        return 0;
}

/**
 * socket_dequeue() - fetch message from input buffer
 * @socket:             socket to operate on
 * @messagep:           output argument for read message
 *
 * This fetches a message from the input buffer. If a full message was parsed,
 * the @messagep argument will now point to it and own a single reference to be
 * released by the caller.
 * If no more messages can be fetched from the input buffer, NULL is put into
 * @messagep.
 *
 * If the input stream was shutdown, SOCKET_E_EOF is returned and no further
 * data can be read.
 *
 * Return: On success, 0 is returned and @messagep will point to the read
 *         message (now owned by the caller). If no more messages can be
 *         fetched, NULL is put into @messagep.
 *         If the input-stream was closed and no more data is to be read,
 *         SOCKET_E_EOF is returned.
 *         On fatal errors, a negative error code is returned.
 */
int socket_dequeue(Socket *socket, Message **messagep) {
        MessageHeader header;
        Message *msg;
        size_t n, n_data;
        int r;

        socket_lines_done(socket);

        msg = socket->in.pending_message;
        n_data = socket->in.data_end - socket->in.data_start;

        if (!msg) {
                n = sizeof(MessageHeader);
                if (_c_unlikely_(n_data < n)) {
                        socket->in.cursor = socket->in.data_end;
                        goto out_nodata;
                }

                memcpy(&header, socket->in.data + socket->in.data_start, n);

                r = message_new_incoming(&msg, header);
                if (r == MESSAGE_E_CORRUPT_HEADER ||
                    r == MESSAGE_E_TOO_LARGE) {
                        /*
                         * Corrupt message headers are considered a protocol
                         * violation and cause an immediate shutdown.
                         */
                        socket_close(socket);
                        return SOCKET_E_EOF;
                } else if (r) {
                        return error_fold(r);
                }

                r = user_charge(socket->user,
                                &socket->in.charge_msg_data,
                                NULL,
                                USER_SLOT_BYTES,
                                sizeof(*msg) + msg->n_data);
                if (r) {
                        msg = message_unref(msg);

                        if (r == USER_E_QUOTA) {
                                socket_close(socket);
                                return SOCKET_E_EOF;
                        }

                        return error_fold(r);
                }

                n_data -= n;
                socket->in.data_start += n;
                socket->in.cursor = socket->in.data_start;
                socket->in.pending_message = msg;
        }

        if (n_data > 0) {
                n = c_min(n_data, msg->n_data - msg->n_copied);
                memcpy(msg->data + msg->n_copied, socket->in.data + socket->in.data_start, n);

                n_data -= n;
                socket->in.data_start += n;
                socket->in.cursor += n;
                msg->n_copied += n;
        }

        if (_c_unlikely_(!n_data && socket->in.fds)) {
                if (msg->fds) {
                        /*
                         * FDs must be transmitted in a single set, anything
                         * else is a protocol violation and will cause an
                         * immediate shutdown.
                         */
                        socket_close(socket);
                        return SOCKET_E_EOF;
                }

                msg->fds = socket->in.fds;
                socket->in.fds = NULL;

                memcpy(&socket->in.charge_msg_fds,
                       &socket->in.charge_buf_fds,
                       sizeof(socket->in.charge_buf_fds));
                socket->in.charge_buf_fds = (UserCharge)USER_CHARGE_INIT;
        }

        if (msg->n_copied >= msg->n_data) {
                *messagep = msg;
                socket->in.pending_message = NULL;
                user_charge_deinit(&socket->in.charge_msg_data);
                user_charge_deinit(&socket->in.charge_msg_fds);
                return 0;
        }

out_nodata:
        socket_might_reset(socket);
        if (_c_unlikely_(socket->hup_in))
                return SOCKET_E_EOF;

        *messagep = NULL;
        return 0;
}

/**
 * socket_queue_line() - queue line on socket
 * @socket:             socket to operate on
 * @user:               user to account for, or NULL
 * @line_in:            line pointer
 * @n:                  length of line
 *
 * This queues the line (@line_in, @n) on the socket @socket, accounting @user
 * as the sender. If @user is NULL, the owner of the socket is accounted.
 *
 * \r\n is always appended to the message by this function.
 *
 * Return: 0 on success, SOCKET_E_QUOTA if quota failed, SOCKET_E_SHUTDOWN if
 *         write-side end is already shutdown, negative error code on failure.
 */
int socket_queue_line(Socket *socket, User *user, const char *line_in, size_t n) {
        SocketBuffer *buffer;
        char *line_out;
        size_t *pos;
        int r;

        if (_c_unlikely_(socket->hup_out || socket->shutdown))
                return SOCKET_E_SHUTDOWN;

        buffer = c_list_last_entry(&socket->out.queue, SocketBuffer, link);
        if (!buffer || n + strlen("\r\n") > socket_buffer_get_line_space(buffer)) {
                r = socket_buffer_new_line(&buffer, socket, user, n + strlen("\r\n"));
                if (r)
                        return error_trace(r);

                c_list_link_tail(&socket->out.queue, &buffer->link);
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
 * socket_queue() - queue socket buffer on socket
 * @socket:             socket to operate on
 * @user:               user to charge as
 * @message:            message to queue
 *
 * This queues @message on the socket @socket, charging @user for the required
 * quota on the socket owner of @socket.
 *
 * Return: 0 on success, SOCKET_E_QUOTA if quota failed, SOCKET_E_SHUTDOWN if
 *         write-side end is already shutdown, negative error code on failure.
 */
int socket_queue(Socket *socket, User *user, Message *message) {
        _c_cleanup_(socket_buffer_freep) SocketBuffer *buffer = NULL;
        int r;

        if (_c_unlikely_(socket->hup_out || socket->shutdown))
                return SOCKET_E_SHUTDOWN;

        r = socket_buffer_new_message(&buffer, socket, user, message);
        if (r)
                return error_trace(r);

        c_list_link_tail(&socket->out.queue, &buffer->link);
        buffer = NULL;
        return 0;
}

static int socket_recvmsg(Socket *socket, void *buffer, size_t max, size_t *from, size_t to, FDList **fdsp) {
        union {
                struct cmsghdr cmsg;
                char buffer[CMSG_SPACE(sizeof(int) * SOCKET_FD_MAX)];
        } control;
        struct cmsghdr *cmsg;
        struct msghdr msg;
        int r, *fds = NULL;
        size_t n_fds = 0;
        ssize_t l;

        assert(to > *from);

        msg = (struct msghdr){
                .msg_iov = &(struct iovec){
                        .iov_base = buffer + *from,
                        .iov_len = c_min(to - *from, max),
                },
                .msg_iovlen = 1,
                .msg_control = &control,
                .msg_controllen = sizeof(control),
        };

        l = recvmsg(socket->fd, &msg, MSG_DONTWAIT | MSG_CMSG_CLOEXEC);
        if (_c_unlikely_(!l)) {
                /*
                 * A 0 return of recvmsg() signals end-of-file. Hence, hangup
                 * the input side, but keep the output alive. We might still
                 * want to flush more data out.
                 */
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
                        /*
                         * If recvmsg(2) fails, this means both read-side *and*
                         * write-side are shutdown. A mere read-side hangup is
                         * signalled by a 0 return-value (handled above).
                         */
                        socket_hangup_input(socket);
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
                }
        }

        if (msg.msg_flags & MSG_CTRUNC) {
                /*
                 * This flag means the control-buffer was too small to retrieve
                 * all data. If this can be triggered remotely, it means a peer
                 * can cause us to miss FDs. Hence, we really must protect
                 * against this.
                 * We do provide suitably sized buffers to be prepared for any
                 * possible scenario. So if this happens, something is fishy
                 * and we better report it.
                 * Note that this is also reported by the kernel if we exceeded
                 * our NOFILE limit. Since this implies resource
                 * misconfiguration as well, we treat it the same way.
                 */
                r = error_origin(-ENOTRECOVERABLE);
                goto error;
        }

        if (_c_unlikely_(n_fds)) {
                /*
                 * So we received FDs with this hunk. If we already got FDs for
                 * this pending message, we must follow the D-Bus spec and
                 * treat this as protocol violation. So close the socket
                 * immediately. We also close the socket immediately in case
                 * the sending user's fd quota has been exceeded.
                 * Otherwise, remember the FDs in the socket. Note that FDs
                 * always belong to the *last* byte of a received hunk, since
                 * the kernel breaks SKBs *AFTER* FDs, but not before them.
                 * This also means we must never call into recvmsg(2) if there
                 * is unparsed data in our buffers, since we might incorrectly
                 * merge two messages.
                 */

                if (_c_unlikely_(*fdsp)) {
                        socket_close(socket);
                        r = SOCKET_E_LOST_INTEREST;
                        goto error;
                }

                r = user_charge(socket->user,
                                &socket->in.charge_buf_fds,
                                NULL,
                                USER_SLOT_FDS,
                                n_fds);
                if (r == USER_E_QUOTA) {
                        /*
                         * Too many/large outstanding messages accross all
                         * a user's peers is considered a protocol
                         * violation too and causes an immediate shutdown.
                         */
                        socket_close(socket);
                        r = SOCKET_E_LOST_INTEREST;
                        goto error;
                } else if (r) {
                        r = error_fold(r);
                        goto error;
                }

                r = fdlist_new_consume_fds(fdsp, fds, n_fds);
                if (r) {
                        user_charge_deinit(&socket->in.charge_buf_fds);
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
        Message *msg = socket->in.pending_message;
        void *p;
        int r;

        if (socket->hup_in)
                return SOCKET_E_LOST_INTEREST;

        /*
         * Always shift the input buffer. In case of the line-parser this
         * should never happen in normal operation: the only way to leave
         * behind a partial line is by filling the whole buffer, in that case
         * at most SOCKET_DATA_RECV_MAX bytes need to be moved. And for the
         * message-parser, there can be at most one message header left
         * behind (16 bytes).
         */
        memmove(socket->in.data,
                socket->in.data + socket->in.data_start,
                socket->in.data_end - socket->in.data_start);
        socket->in.cursor -= socket->in.data_start;
        socket->in.data_end -= socket->in.data_start;
        socket->in.data_start = 0;

        /*
         * Never ever read data if we did not finish parsing our input buffer!
         *
         * This is crucial! The kernel provides auxiliary data that is attached
         * to specific SKBs, and as such part of the stream. We must never
         * merge them across D-Bus message boundaries (see the FD handling on
         * recvmsg(2) for details).
         *
         * As a consequence of this, we know that either our input buffer is
         * empty, or we have no partial message pending. This stems from our
         * parser to always copy any outstanding bytes from the input buffer
         * into a pending message, and returning the message when done. So
         * either we fully parsed a message and returned it (thus @msg is NULL)
         * or our last dequeue-call emptied the input buffer by copying into
         * the pending message.
         */
        if (socket->in.cursor < socket->in.data_end || (msg && msg->n_copied >= msg->n_data))
                return 0;

        assert(!msg || !socket->in.cursor);

        /*
         * In case our input buffer is full, we need to resize it. This can
         * only happen for the line-reader, since messages leave at most 16
         * bytes behind (size of a single header).
         * The line-reader, however, parses the entire line into the input
         * buffer. Hence, in case the normal buffer size is exceeded, we
         * re-allocate to the maximum once.
         *
         * Once we finished reading lines *AND* we processed all the data in
         * the input buffer, we can safely de-allocate the buffer and fall back
         * to the input buffer again.
         */
        if (_c_unlikely_(socket->in.data_size <= socket->in.data_end)) {
                assert(!socket->lines_done);

                if (socket->in.data_size >= SOCKET_LINE_MAX) {
                        socket_close(socket);
                        return SOCKET_E_LOST_INTEREST;
                }

                assert(socket->in.data == socket->input_buffer);

                p = malloc(SOCKET_LINE_MAX);
                if (!p)
                        return error_origin(-ENOMEM);

                r = user_charge(socket->user,
                                &socket->in.charge_buf_data,
                                NULL,
                                USER_SLOT_BYTES,
                                SOCKET_LINE_MAX);
                if (r) {
                        free(p);

                        if (r == USER_E_QUOTA) {
                                socket_close(socket);
                                return SOCKET_E_LOST_INTEREST;
                        }

                        return error_fold(r);
                }

                memcpy(p,
                       socket->in.data + socket->in.data_start,
                       socket->in.data_end - socket->in.data_start);

                socket->in.data = p;
                socket->in.data_size = SOCKET_LINE_MAX;
                socket->in.data_end -= socket->in.data_start;
                socket->in.cursor -= socket->in.data_start;
                socket->in.data_start = 0;
        } else if (_c_unlikely_(socket->in.data != socket->input_buffer)) {
                if (socket->lines_done) {
                        assert(!socket->in.data_start);
                        assert(socket->in.data_end <= sizeof(socket->input_buffer));

                        memcpy(socket->input_buffer, socket->in.data, socket->in.data_end);
                        free(socket->in.data);
                        socket->in.data = socket->input_buffer;
                        socket->in.data_size = sizeof(socket->input_buffer);
                        user_charge_deinit(&socket->in.charge_buf_data);
                }
        }

        /*
         * If there is a pending message, we try to read directly into it,
         * skipping the separate socket input buffer. However, we only do this
         * if the hunk of data to fetch is bigger than (or equal to) our input
         * buffer. This avoids fetching small amounts of data from the kernel,
         * while we could fetch big hunks of consecutive small messages.
         *
         * In other words: If a message is considerably big, we will read it
         *                 directly into its message object (single copy). In
         *                 all other cases, we first read from the kernel into
         *                 our input buffer (possibly fetching many messages at
         *                 once), and then copy over the actual data into the
         *                 message objects (double copy).
         *                 This is a trade-off between double-copy and reducing
         *                 the number of calls to recvmsg(2).
         */
        if (msg && msg->n_data - msg->n_copied >= socket->in.data_size - socket->in.data_end)
                return socket_recvmsg(socket,
                                      msg->data,
                                      msg->n_data,
                                      &msg->n_copied,
                                      msg->n_data,
                                      &msg->fds);

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
                              socket->in.data_size,
                              &socket->in.fds);
}

static int socket_dispatch_write(Socket *socket) {
        SocketBuffer *buffer, *safe;
        struct mmsghdr msgs[SOCKET_MMSG_MAX];
        struct msghdr *msg;
        int i, n_msgs;

        if (socket->hup_out)
                return SOCKET_E_LOST_INTEREST;

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
                case ETOOMANYREFS:
                        /*
                         * XXX: Kernel might return ETOOMANYREFS if we ever hit
                         *      the fd-passing recursion limit. There are
                         *      pending patches to drop this, but we should
                         *      really review our behavior, once the discussion
                         *      settled. Until then, we simply disconnect the
                         *      destination as a last resort.
                         *
                         *      Note that ETOOMANYREFS is also returned if we
                         *      have too many FDs inflight. In this case we
                         *      should simply exit with an error code and
                         *      require the user to extend our resource limits.
                         *      The quota accounting should be configured
                         *      sufficiently, according to the resources given
                         *      to the broker.
                         */
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
                if (_c_unlikely_(socket->shutdown))
                        socket_shutdown_now(socket);
                return SOCKET_E_LOST_INTEREST;
        }

        return 0;
}

/**
 * socket_dispatch() - dispatch event
 * @socket:             socket to operate on
 * @event:              epoll-event to dispatch
 *
 * This dispatches the epoll-event @event on the socket @socket. After calling
 * this, the caller must loop on socket_dequeue{,_line}() to fetch all data.
 *
 * Return: 0 on success, SOCKET_E_LOST_INTEREST if the socket lost interest in
 *         the event, SOCKET_E_PREEMPTED if the socket was preempted while
 *         handling the event, negative error code on failure.
 */
int socket_dispatch(Socket *socket, uint32_t event) {
        int r = SOCKET_E_LOST_INTEREST;

        switch (event) {
        case EPOLLIN:
                r = socket_dispatch_read(socket);
                break;
        case EPOLLOUT:
                r = socket_dispatch_write(socket);
                break;
        case EPOLLHUP:
                socket_hangup_output(socket);
                break;
        }

        return r;
}

/**
 * socket_shutdown() - disallow further queueing on the socket
 * @socket:             socket to operate on
 *
 * This disallows further queuing on the socket, but still flushes out the
 * pending socket buffers to the kernel. Once all pending output has been
 * sent the remote end is notified of the shutdown.
 */
void socket_shutdown(Socket *socket) {
        if (!socket->shutdown) {
                socket->shutdown = true;
                if (c_list_is_empty(&socket->out.queue))
                        socket_shutdown_now(socket);
        }
}

/**
 * socket_close() - close both communication directions
 * @socket:                     socket to operate on
 *
 * This disallows both further queuing and dequeuing on the socket, but
 * still flushes out the pending socket buffers to the kernel. Once all
 * pending output has been sent the remote end is notified of the shutdown.
 */
void socket_close(Socket *socket) {
        socket_hangup_input(socket);
        socket_shutdown(socket);

        /*
         * Now that both input and output were shut down, we discard pending
         * input, since we want an immediate shutdown.
         * Note that this might trigger a reset, so we have to call into
         * socket_might_reset() here (the call to socket_discard_input() does
         * not do that).
         */
        socket_discard_input(socket);
        socket_might_reset(socket);
}
