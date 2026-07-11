/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: D-Bus Broker Developers */

/*
 * Test log context helpers
 */

#undef NDEBUG
#include <c-stdaux.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include "util/log.h"

/*
 * In lossy mode, a journal that is gone (its socket closed, e.g. a journald
 * restart recreated its sockets and orphaned this long-connected client)
 * must lead to dropped messages, not to a fatal error: log emission
 * failures escalating out of the log layer took the whole broker down in
 * production.
 */
static void test_lossy_journal_gone(void) {
        _c_cleanup_(log_deinit) Log log = LOG_NULL;
        int fds[2], r;

        r = socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, fds);
        c_assert(!r);

        log_init_journal_consume(&log, fds[0]);
        log_set_lossy(&log, true);

        /* Peer closed: send(2) on the connected datagram socket now fails
         * with ECONNREFUSED. */
        close(fds[1]);

        log_append_here(&log, LOG_WARNING, 0, NULL);
        r = log_commitf(&log, "diagnostic while journal is gone\n");
        c_assert(!r);

        /* Subsequent messages keep being dropped silently. */
        log_append_here(&log, LOG_WARNING, 0, NULL);
        r = log_commitf(&log, "another diagnostic\n");
        c_assert(!r);
}

/*
 * In lossy mode, a full journal socket queue (EAGAIN) drops messages; this
 * covered the pre-existing lossy path and must keep working alongside the
 * unavailable-journal handling.
 */
static void test_lossy_journal_full(void) {
        _c_cleanup_(log_deinit) Log log = LOG_NULL;
        int fds[2], r;

        r = socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, fds);
        c_assert(!r);

        log_init_journal_consume(&log, fds[0]);
        log_set_lossy(&log, true);

        /* Nobody reads fds[1]: fill the queue until EAGAIN, all calls must
         * still report success. */
        for (unsigned int i = 0; i < 1024; ++i) {
                log_append_here(&log, LOG_WARNING, 0, NULL);
                r = log_commitf(&log, "flood diagnostic %u\n", i);
                c_assert(!r);
        }

        close(fds[1]);
}

int main(int argc, char **argv) {
        test_lossy_journal_gone();
        test_lossy_journal_full();
        return 0;
}
