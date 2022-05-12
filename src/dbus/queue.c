/*
 * D-Bus Input/Output Queues
 */

#include <c-stdaux.h>
#include <stdlib.h>
#include "dbus/queue.h"
#include "util/fdlist.h"
#include "util/error.h"

/**
 * iqueue_init() - XXX
 */
void iqueue_init(IQueue *iq, User *user) {
        *iq = (IQueue)IQUEUE_NULL(*iq);
        iq->user = user_ref(user);
}

/**
 * iqueue_deinit() - XXX
 */
void iqueue_deinit(IQueue *iq) {
        iqueue_flush(iq);

        c_assert(!iq->fds);
        c_assert(!iq->pending.data);
        c_assert(!iq->pending.fds);

        if (iq->data != iq->buffer) {
                free(iq->data);
                iq->data = iq->buffer;
                iq->data_size = sizeof(iq->buffer);
        }

        user_charge_deinit(&iq->pending.charge_fds);
        user_charge_deinit(&iq->pending.charge_data);
        user_charge_deinit(&iq->charge_fds);
        user_charge_deinit(&iq->charge_data);

        iq->user = user_unref(iq->user);
}

/**
 * iqueue_flush() - XXX
 */
void iqueue_flush(IQueue *iq) {
        iq->data_start = 0;
        iq->data_end = 0;
        iq->data_cursor = 0;
        iq->fds = fdlist_free(iq->fds);

        iq->pending.data = NULL;
        iq->pending.n_data = 0;
        iq->pending.n_copied = 0;
        iq->pending.fds = fdlist_free(iq->pending.fds);

        user_charge_deinit(&iq->charge_fds);
        user_charge_deinit(&iq->pending.charge_fds);
        user_charge_deinit(&iq->pending.charge_data);
}

/**
 * iqueue_set_pending() - XXX
 */
int iqueue_set_target(IQueue *iq, void *data, size_t n_data) {
        int r;

        c_assert(data);
        c_assert(!iq->pending.data);

        /*
         * This temporarily charges the pending buffer on @iq->user, so a
         * single user cannot pin arbitrary memory as pending input buffers
         * without every completing a message.
         * Note that this charge only applies to the *pinned* buffer. As long
         * as the message is not pinned, it is not charged on anyone. We
         * consider each dispatch thread to be capable of holding at least a
         * single message at all times, so no need to charge them unless we pin
         * them on a peer.
         */
        r = user_charge(iq->user,
                        &iq->pending.charge_data,
                        NULL,
                        USER_SLOT_BYTES,
                        n_data);
        if (r)
                return (r == USER_E_QUOTA) ? IQUEUE_E_QUOTA : error_fold(r);

        iq->pending.data = data;
        iq->pending.n_data = n_data;
        iq->pending.n_copied = 0;
        /* FDs stay untouched and are merged into the next blob */

        return 0;
}

/**
 * iqueue_get_cursor() - XXX
 */
int iqueue_get_cursor(IQueue *iq,
                      void **bufferp,
                      size_t **fromp,
                      size_t *top,
                      FDList ***fdsp,
                      UserCharge **charge_fdsp) {
        void *p;
        int r;

        /*
         * Always shift the input buffer. In case of the line-parser this
         * should never happen in normal operation: the only way to leave
         * behind a partial line is by filling the whole buffer, in that case
         * at most IQUEUE_RECV_MAX bytes need to be moved. And for the
         * message-parser, there can be at most one message header left
         * behind (16 bytes).
         *
         * Long story short: We never shift more than 16 bytes in a fast-path,
         *                   or you are doing something wrong.
         */
        memmove(iq->data,
                iq->data + iq->data_start,
                iq->data_end - iq->data_start);
        iq->data_cursor -= iq->data_start;
        iq->data_end -= iq->data_start;
        iq->data_start = 0;

        /*
         * Never ever read data if we did not finish parsing our input buffer!
         *
         * This is crucial! The kernel provides auxiliary data that is attached
         * to specific SKBs, and as such part of the stream. We must never
         * merge them across D-Bus message boundaries (see the FD handling on
         * recvmsg(2) for details). Hence, you must always dispatch your entire
         * input-queue before reading more data.
         */
        if (iq->data_cursor < iq->data_end)
                return IQUEUE_E_PENDING;

        /*
         * In case our input buffer is full, we need to resize it. This can
         * only happen for the line-reader, since otherwise we always read into
         * separate buffers.
         * The line-reader, however, parses the entire line into the input
         * buffer. Hence, in case the normal buffer size is exceeded, we
         * re-allocate to its maximum *ONCE*.
         *
         * Once we finished reading lines *AND* we processed all the data in
         * the input buffer, we can safely de-allocate the buffer and fall back
         * to the input buffer again.
         */
        if (_c_unlikely_(iq->data_size <= iq->data_end)) {
                if (iq->data_size >= IQUEUE_LINE_MAX)
                        return IQUEUE_E_VIOLATION;

                p = malloc(IQUEUE_LINE_MAX);
                if (!p)
                        return error_origin(-ENOMEM);

                r = user_charge(iq->user,
                                &iq->charge_data,
                                NULL,
                                USER_SLOT_BYTES,
                                IQUEUE_LINE_MAX);
                if (r) {
                        free(p);
                        return (r == USER_E_QUOTA) ? IQUEUE_E_QUOTA : error_fold(r);
                }

                /* we always shift so data_start must be 0 */
                c_assert(!iq->data_start);
                c_assert(iq->data == iq->buffer);

                c_memcpy(p, iq->data, iq->data_end);
                iq->data = p;
                iq->data_size = IQUEUE_LINE_MAX;
        } else if (_c_unlikely_(iq->data != iq->buffer && iq->pending.data)) {
                c_assert(!iq->data_start);
                c_assert(iq->data_end <= sizeof(iq->buffer));

                c_memcpy(iq->buffer, iq->data, iq->data_end);
                free(iq->data);
                user_charge_deinit(&iq->charge_data);
                iq->data = iq->buffer;
                iq->data_size = sizeof(iq->buffer);
        }

        /*
         * If there is a pending buffer, we try to read directly into it,
         * skipping the separate input buffer. However, we only do this if the
         * chunk of data to fetch is bigger than (or equal to) our input
         * buffer. This avoids fetching small amounts of data from the kernel,
         * while we could fetch big chunks of consecutive small messages.
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
        if (iq->pending.n_data - iq->pending.n_copied >= iq->data_size - iq->data_end) {
                *bufferp = iq->pending.data;
                *fromp = &iq->pending.n_copied;
                *top = iq->pending.n_data;
                *fdsp = &iq->pending.fds;
                *charge_fdsp = &iq->pending.charge_fds;
                return 0;
        }

        /*
         * Read more data into the input buffer, and store the file-descriptors
         * in the buffer as well.
         *
         * Only ever read in IQUEUE_RECV_MAX in order to limit the number of
         * incoming messages we may have in the buffer at once.
         *
         * Note that the kernel always breaks recvmsg() calls after an SKB with
         * file-descriptor payload. Hence, this could be improvded with
         * recvmmsg() so we get multiple messages at all cost. However, FD
         * passing is no fast-path and should never be, so there is little
         * reason to resort to recvmmsg() (which would be non-trivial, anyway,
         * since we would need multiple input buffers).
         */
        *bufferp = iq->data;
        *fromp = &iq->data_end;
        *top = (iq->data_size - iq->data_end) > IQUEUE_RECV_MAX ? iq->data_end + IQUEUE_RECV_MAX : iq->data_size;
        *fdsp = &iq->fds;
        *charge_fdsp = &iq->charge_fds;
        return 0;
}

/**
 * iqueue_pop_line() - XXX
 */
int iqueue_pop_line(IQueue *iq, const char **linep, size_t *np) {
        char *line;
        size_t n;

        c_assert(!iq->pending.data);

        /*
         * Advance our cursor byte by byte and look for an end-of-line. We
         * remember the cursor position, so no byte is ever parsed twice.
         */
        for ( ; iq->data_cursor < iq->data_end; ++iq->data_cursor) {
                /*
                 * If we are at the end of the input-queue, we must consume
                 * any possible FD array that we received alongside it.
                 * The kernel always breaks _after_ skbs with FDs, but not
                 * before them. Hence, FDs are attached to the LAST byte of our
                 * input-queue, rather than the first.
                 *
                 * During line-handling, we consider receiving FDs a protocl
                 * violation, and the DBus spec clearly states that no
                 * extension shall pass FDs during authentication.
                 */
                if (iq->data_cursor + 1 >= iq->data_end) {
                        if (_c_unlikely_(fdlist_count(iq->fds) > 0))
                                return IQUEUE_E_VIOLATION;
                }

                /*
                 * If we find an \r\n, return the pointer and length to the
                 * caller and cut out the line.
                 * We do NOT copy the line. We leave it in the buffer untouched
                 * and return a direct pointer into the buffer. The pointer is
                 * only valid until the next call into this object.
                 * While we replace \r by NUL, this is not meant to be relied
                 * upon by the caller. It is a pure safety belt. The caller
                 * better not accesses the buffer beyond the returned line
                 * length.
                 */
                if (iq->data_cursor > 0 &&
                    iq->data[iq->data_cursor] == '\n' &&
                    iq->data[iq->data_cursor - 1] == '\r') {
                        /* remember start and length without \r\n */
                        line = iq->data + iq->data_start;
                        n = iq->data_cursor - iq->data_start - 1;

                        /* advance cursor and cut buffer */
                        iq->data_start = ++iq->data_cursor;

                        /* replace \r by safety NUL and return to caller */
                        line[n] = 0;
                        *linep = (const char *)line;
                        *np = n;
                        return 0;
                }
        }

        return IQUEUE_E_PENDING;
}

/**
 * iqueue_pop_data() - XXX
 */
int iqueue_pop_data(IQueue *iq, FDList **fdsp) {
        size_t n, n_data;

        c_assert(iq->pending.data);
        c_assert(iq->pending.n_copied <= iq->pending.n_data);

        n_data = iq->data_end - iq->data_start;

        /*
         * As long as there is data in our input-queue, and the pending buffer
         * is not fully read, we continously copy over data from the
         * input-queue into the pending buffer. Note that this step might be
         * short-cut by the socket-layer by directly reading data into the
         * pending buffer.
         */
        if (n_data > 0) {
                n = c_min(n_data, iq->pending.n_data - iq->pending.n_copied);

                c_memcpy(iq->pending.data + iq->pending.n_copied,
                         iq->data + iq->data_start,
                         n);

                n_data -= n;
                iq->data_start += n;
                iq->data_cursor += n;
                iq->pending.n_copied += n;
        }

        /*
         * Auxiliary file-descriptors are returned by the kernel together with
         * message data. The kernel breaks the receiption *after* each skbuff
         * that carried FDs. Hence, FDs are always attached to the *last* byte
         * of the data-buffer they were returned with.
         * D-Bus clients are required to send FDs together with the bytes of
         * their message. Hence, they cannot merge multiple messages into a
         * single buffer, if they carry FDs. The worst that can happen is that
         * many non-fd-carrying messages are merged into a single SKB up until
         * (and including) a last message that carries FDs. Since we attribute
         * FDs to the last byte of our received chunks, we will correctly
         * attribute the FDs to the last message.
         *
         * So, whenever we copied over the last byte from the input-queue into
         * a message, this means we also need to copy the FDs. Note that the
         * D-Bus spec does *NOT* allow multiple FD-Sets to be transferred with
         * a single message (all FDs must be transferred in a single shot). It
         * is, thus, a protocol violation if there are multiple FDsets for a
         * single message.
         */
        if (_c_unlikely_(!n_data && iq->fds)) {
                if (_c_unlikely_(iq->pending.fds))
                        return IQUEUE_E_VIOLATION;

                iq->pending.fds = iq->fds;
                iq->pending.charge_fds = iq->charge_fds;
                iq->fds = NULL;
                iq->charge_fds = (UserCharge)USER_CHARGE_INIT;
        }

        /*
         * If the pending message is not finished, yet, let the caller know
         * that we need more data.
         */
        if (iq->pending.n_copied < iq->pending.n_data)
                return IQUEUE_E_PENDING;

        /*
         * The pending message has been fully received. Deaccount it, since it
         * is now owned by the calling thread and will be charged on whoever
         * pins the message next. Unpin the message from the input-queue and
         * transfer ownership to the caller.
         */
        if (fdsp) {
                *fdsp = iq->pending.fds;
                iq->pending.fds = NULL;
                user_charge_deinit(&iq->pending.charge_fds);
        }
        iq->pending.data = NULL;
        iq->pending.n_data = 0;
        iq->pending.n_copied = 0;
        user_charge_deinit(&iq->pending.charge_data);
        return 0;
}
