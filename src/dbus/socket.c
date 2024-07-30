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
#include <c-stdaux.h>
#include <linux/sockios.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include "dbus/message.h"
#include "dbus/queue.h"
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
        c_list_unlink(&buffer->link);
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
        c_memcpy(buffer->vecs, message->vecs, sizeof(message->vecs));

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

        c_assert(!buffer->message);

        n_remaining = buffer->n_total;
        n_remaining -= (char *)buffer->vecs[0].iov_base - socket_buffer_get_base(buffer);
        n_remaining -= buffer->vecs[0].iov_len;

        return n_remaining;
}

static void socket_buffer_get_line_cursor(SocketBuffer *buffer, char **datap, size_t **posp) {
        c_assert(!buffer->message);

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
                // IOVs can be empty/NULL. Ensure we do not calculate
                // `NULL + 0`, as this is, unfortunately, UB.
                if (t) {
                        buffer->writer->iov_len -= t;
                        buffer->writer->iov_base += t;
                        n -= t;
                }
                if (buffer->writer->iov_len)
                        break;
        }

        c_assert(!n);

        return socket_buffer_is_consumed(buffer);
}

static void socket_discard_input(Socket *socket) {
        iqueue_flush(&socket->in.queue);
        socket->in.message = message_unref(socket->in.message);
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
 */
void socket_init(Socket *socket, User *user, int fd) {
        *socket = (Socket)SOCKET_NULL(*socket);
        socket->user = user_ref(user);
        socket->fd = fd;
        iqueue_init(&socket->in.queue, user);
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
        SocketBuffer *buffer;

        socket_discard_input(socket);
        socket_discard_output(socket);

        while ((buffer = c_list_first_entry(&socket->out.pending, SocketBuffer, link)))
                socket_buffer_free(buffer);

        c_assert(c_list_is_empty(&socket->out.pending));
        c_assert(c_list_is_empty(&socket->out.queue));
        c_assert(!socket->in.message);

        iqueue_deinit(&socket->in.queue);
        socket->fd = -1;
        socket->user = user_unref(socket->user);
}

static void socket_might_reset(Socket *socket) {
        if (_c_unlikely_(!socket->reset &&
                         socket->hup_in &&
                         socket->hup_out &&
                         c_list_is_empty(&socket->out.pending) &&
                         iqueue_is_eof(&socket->in.queue)))
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

        c_assert(socket->shutdown);

        if (!socket->hup_out) {
                r = shutdown(socket->fd, SHUT_WR);
                c_assert(r >= 0);

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
        int r;

        r = iqueue_pop_line(&socket->in.queue, linep, np);
        if (r) {
                if (r == IQUEUE_E_PENDING) {
                        socket_might_reset(socket);
                        if (_c_unlikely_(socket->hup_in))
                                return SOCKET_E_EOF;

                        *linep = NULL;
                        *np = 0;
                        return 0;
                } else if (r == IQUEUE_E_VIOLATION) {
                        socket_close(socket);
                        return SOCKET_E_EOF;
                }

                return error_fold(r);
        }

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
 *         If the incoming message would exceed the quota of the caller, then
 *         SOCKET_E_QUOTA is returned.
 *         On fatal errors, a negative error code is returned.
 */
int socket_dequeue(Socket *socket, Message **messagep) {
        Message *message;
        int r;

        if (!iqueue_get_target(&socket->in.queue)) {
                r = iqueue_set_target(&socket->in.queue,
                                      &socket->in.header,
                                      sizeof(socket->in.header));
                if (r)
                        return (r == IQUEUE_E_QUOTA) ? SOCKET_E_QUOTA : error_fold(r);
        }

        if (!socket->in.message) {
                r = iqueue_pop_data(&socket->in.queue, NULL);
                if (r == IQUEUE_E_PENDING) {
                        goto nodata;
                } else if (r == IQUEUE_E_VIOLATION) {
                        socket_close(socket);
                        return SOCKET_E_EOF;
                } else if (r) {
                        return error_fold(r);
                }

                r = message_new_incoming(&message, socket->in.header);
                if (r == MESSAGE_E_CORRUPT_HEADER ||
                    r == MESSAGE_E_TOO_LARGE) {
                        socket_close(socket);
                        return SOCKET_E_EOF;
                } else if (r) {
                        return error_fold(r);
                }

                r = iqueue_set_target(&socket->in.queue,
                                      message->data + sizeof(socket->in.header),
                                      message->n_data - sizeof(socket->in.header));
                if (r) {
                        message_unref(message);
                        return (r == IQUEUE_E_QUOTA) ? SOCKET_E_QUOTA : error_fold(r);
                }

                socket->in.message = message;
        }

        c_assert(socket->in.message);

        r = iqueue_pop_data(&socket->in.queue, &socket->in.message->fds);
        if (r == IQUEUE_E_PENDING) {
                goto nodata;
        } else if (r == IQUEUE_E_VIOLATION) {
                socket_close(socket);
                return SOCKET_E_EOF;
        } else if (r) {
                return error_fold(r);
        }

        *messagep = socket->in.message;
        socket->in.message = NULL;
        return 0;

nodata:
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

        c_memcpy(line_out, line_in, n);
        line_out += n;
        *pos += n;

        c_memcpy(line_out, "\r\n", strlen("\r\n"));
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

static int socket_recvmsg(Socket *socket,
                          void *buffer,
                          size_t *from,
                          size_t to,
                          FDList **fdsp,
                          UserCharge *charge_fds) {
        union {
                struct cmsghdr cmsg;
                char buffer[CMSG_SPACE(sizeof(int) * SOCKET_FD_MAX)];
        } control;
        struct cmsghdr *cmsg;
        struct msghdr msg;
        int r, *fds = NULL;
        size_t n_fds = 0;
        ssize_t l;

        c_assert(to > *from);

        msg = (struct msghdr){
                .msg_iov = &(struct iovec){
                        .iov_base = buffer + *from,
                        .iov_len = to - *from,
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
                        c_assert(!n_fds);
                        fds = (void *)CMSG_DATA(cmsg);
                        n_fds = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);
                        c_assert(n_fds <= SOCKET_FD_MAX);
                }
        }

        if (msg.msg_flags & MSG_CTRUNC) {
                /*
                 * Our control-buffer-size is carefully calculated to be big
                 * enough for any possible ancillary data we expect. Therefore,
                 * the kernel should never be required to truncate it, and thus
                 * MSG_CTRUNC will never be set. This is also foward compatible
                 * to future extensions to the ancillary data, since these must
                 * be enabled explicitly before the kernel considers forwarding
                 * them.
                 *
                 * Unfortunately, the SCM_RIGHTS implementation might set this
                 * flag as well. In particular, if not all FDs can be returned
                 * to user-space, MSG_CTRUNC will be set (signalling that the
                 * FD-set is non-complete). No other error is returned or
                 * signalled, though. There are several reasons why the FD
                 * transmission can fail. Most importantly, if we exhaust our
                 * FD limit, further FDs will simply be discarded. We are
                 * protected against this by our accounting-quotas, but we
                 * would still like to catch this condition and warn loudly.
                 * However, FDs are also dropped if the security layer refused
                 * the transmission of the FD in question. This means, if an
                 * LSM refuses the D-Bus client to send us an FD, the FD is
                 * just dropped and MSG_CTRUNC will be set. This can be
                 * triggered by clients.
                 *
                 * To summarize: In an ideal world, we would expect this flag
                 * to never be set, and we would just use
                 * `error_origin(-ENOTRECOVERABLE)` to provide diagnostics.
                 * Unfortunately, the gross misuse of this flag for LSM
                 * security enforcements means we have to assume any occurence
                 * of MSG_CTRUNC means the client was refused to send a
                 * specific message. Our only possible way to deal with this is
                 * to disconnect the client.
                 */
                socket_close(socket);
                r = SOCKET_E_LOST_INTEREST;
                goto error;
        }

        if (_c_unlikely_(*fdsp && n_fds)) {
                /* XXX: this is a protocol violation, but for now simply drop the
                 *      spurios fds as sd-bus is broken and passes us this.
                 *      This whole conditional should simply be dropped.
                 */
                while (n_fds)
                        close(fds[--n_fds]);

                fprintf(stderr, "socket: discarded unexpected file descriptors.\n");
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
                                charge_fds,
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
                        user_charge_deinit(charge_fds);
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
        UserCharge *charge_fds;
        size_t *from, to;
        FDList **fds;
        void *buffer;
        int r;

        if (socket->hup_in)
                return SOCKET_E_LOST_INTEREST;

        r = iqueue_get_cursor(&socket->in.queue,
                              &buffer,
                              &from,
                              &to,
                              &fds,
                              &charge_fds);
        if (r == IQUEUE_E_PENDING) {
                return 0;
        } else if (r == IQUEUE_E_QUOTA ||
                   r == IQUEUE_E_VIOLATION) {
                socket_close(socket);
                return SOCKET_E_LOST_INTEREST;
        } else if (r) {
                return error_fold(r);
        }

        return socket_recvmsg(socket,
                              buffer,
                              from,
                              to,
                              fds,
                              charge_fds);
}

static int socket_dispatch_write(Socket *socket) {
        SocketBuffer *buffer, *safe;
        struct mmsghdr msgs[SOCKET_MMSG_MAX];
        struct msghdr *msg;
        int r, i, v, n_msgs;

        if (!c_list_is_empty(&socket->out.pending)) {
                r = ioctl(socket->fd, SIOCOUTQ, &v);
                if (r < 0)
                        return error_origin(-errno);

                /*
                 * We would like to check for an empty queue here:
                 *
                 *     if (v > 0)
                 *             return 0;
                 *
                 * Unfortunately, the kernel uses the write-buffer as a
                 * reference counter. This effectively means that when it drops
                 * buffers from the write-queue, it drops all but 1 from the
                 * `sk_wmem_alloc` counter, then notifies user-space, and
                 * eventually drops its final reference, possibly freeing the
                 * underlying socket structures, if this was the last
                 * reference.
                 *
                 * While it is possible to hit this small race with a single
                 * kernel thread currently holding this temporary reference,
                 * technically there can be many threads in parallel. However,
                 * this would require multiple readers on the other end of the
                 * dbus-socket, and all of them dispatching data in parallel
                 * (which does not make sense for stream sockets), and all in
                 * exactly the same kernel path at the same time. While we
                 * consider it impossible to hit this with more than one thread
                 * in the same path, we use 128 as a safety measure here.
                 *
                 * Note that the kernel uses `skb->truesize` for write-buffer
                 * allocations, meaning that even transmitting a single byte
                 * will allocate buffers larger than 128 bytes. Therefore, this
                 * seems like a suitable tradeoff.
                 *
                 * The preferred fix would be the kernel returning the actual
                 * data, rather than misusing the counter, but that is not how
                 * things currently work.
                 *
                 * Lastly, we simply return 0 and treat this condition as
                 * EAGAIN. We know that the kernel will send us an EPOLLOUT
                 * notification as soon as the write-buffer clears, so we will
                 * be woken up again when there is no more pending data in the
                 * outgoing queues.
                 */
                if (v > 128)
                        return 0;

                c_list_for_each_entry_safe(buffer, safe, &socket->out.pending, link)
                        socket_buffer_free(buffer);

                socket_might_reset(socket);
        }

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
                        msg->msg_controllen = fdlist_size(buffer->message->fds);
                } else {
                        msg->msg_control = NULL;
                        msg->msg_controllen = 0;
                }
                msg->msg_flags = 0;

                if (++n_msgs >= (ssize_t)C_ARRAY_SIZE(msgs))
                        break;

                /*
                 * Right now, the only information the kernel gives us about
                 * outgoing queues is whether there is data queued or not. That
                 * is, a boolean state. There is some other data, but we cannot
                 * reliable deduce any useful state from it.
                 *
                 * Hence, we only ever queue at most 1 message with FDs on it.
                 * This way, we can reliably get notified about FDs being
                 * queued and dequeued.
                 *
                 * We could, technically, avoid this and just spam out
                 * messages. However, we better be notified as early as
                 * possible about dequeued FDs, so our accounting actually
                 * represents the real client-controlled state. If we were
                 * notified late (because we continued queueing), then a client
                 * might have dequeued the FDs at fault, but we still consider
                 * them queued and thus might exceed its quota.
                 */
                if (buffer->message && fdlist_count(buffer->message->fds))
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
                         * The kernel used to return ETOOMANYREFS if we exceed
                         * the fd-passing recursion limit. This was dropped in
                         * commit:
                         *
                         *     commit 27eac47b00789522ba00501b0838026e1ecb6f05
                         *     Author: David Herrmann <dh.herrmann@gmail.com>
                         *     Commit: David S. Miller <davem@davemloft.net>
                         *     Date:   Mon Jul 17 11:35:54 2017 +0200
                         *
                         *         net/unix: drop obsolete fd-recursion limits
                         *
                         * Since then the kernel no longer limits the recursion
                         * depth, thus we will not trigger ETOOMANYREFS. You
                         * are highly recommended to run >=linux-4.14,
                         * otherwise clients can exploit this by modifying
                         * file-descriptors while inflight.
                         *
                         * Note that the kernel also returns ETOOMANYREFS if we
                         * exceeded our per-user limit of maximum inflight
                         * file-descriptors. Since we employ quota-accounting,
                         * ETOOMANYREFS should never occur, unless you
                         * misconfigured your broker. Hence, we treat this as
                         * fatal error.
                         *
                         * XXX: At one point in the future, we should remove
                         *      this switch-case. We leave it here purely for
                         *      documenting the history of this error-code.
                         */
                        break;
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

                if (socket_buffer_consume(buffer, msgs[i].msg_len)) {
                        if (buffer->message && buffer->message->fds) {
                                c_list_unlink(&buffer->link);
                                c_list_link_tail(&socket->out.pending, &buffer->link);
                        } else {
                                socket_buffer_free(buffer);
                        }
                }

                ++i;
        }
        c_assert(i == n_msgs);

        if (c_list_is_empty(&socket->out.queue)) {
                if (_c_unlikely_(socket->shutdown))
                        socket_shutdown_now(socket);

                if (_c_likely_(c_list_is_empty(&socket->out.pending)))
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

/**
 * socket_get_stats() - calculate socket statistics
 * @socket:                     socket to operate on
 * @n_in_bytesp:                output argument for #incoming bytes
 * @n_in_fdsp:                  output argument for #incoming fds
 * @n_out_bytesp:               output argument for #outgoing bytes
 * @n_out_fdsp:                 output argument for #outgoing fds
 *
 * This calculates the statistics of incoming and outgoing messages on @socket.
 */
void socket_get_stats(Socket *socket,
                      unsigned int *n_in_bytesp,
                      unsigned int *n_in_fdsp,
                      unsigned int *n_out_bytesp,
                      unsigned int *n_out_fdsp) {
        unsigned int n_in_bytes = 0, n_in_fds = 0, n_out_bytes = 0, n_out_fds = 0;
        SocketBuffer *buffer;

        n_in_bytes += socket->in.queue.charge_data.charge;
        n_in_bytes += socket->in.queue.pending.charge_data.charge;
        n_in_fds += socket->in.queue.charge_fds.charge;
        n_in_fds += socket->in.queue.pending.charge_fds.charge;

        c_list_for_each_entry(buffer, &socket->out.queue, link) {
                n_out_bytes += buffer->charges[0].charge;
                n_out_fds += buffer->charges[1].charge;
        }

        c_list_for_each_entry(buffer, &socket->out.pending, link) {
                n_out_bytes += buffer->charges[0].charge;
                n_out_fds += buffer->charges[1].charge;
        }

        *n_in_bytesp = n_in_bytes;
        *n_in_fdsp = n_in_fds;
        *n_out_bytesp = n_out_bytes;
        *n_out_fdsp = n_out_fds;
}
