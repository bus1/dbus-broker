/*
 * Test Dispatcher
 */

#undef NDEBUG
#include <c-stdaux.h>
#include <linux/sockios.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include "util/dispatch.h"

static void q_assert(int s, bool has_in, bool has_out) {
        int r, v;

        /*
         * Verify that the IN/OUT queues are (non-)empty, depending on what is
         * given as @has_in and @has_out.
         */

        r = ioctl(s, SIOCINQ, &v);
        c_assert(r >= 0);
        c_assert(!v == !has_in);

        r = ioctl(s, SIOCOUTQ, &v);
        c_assert(r >= 0);
        c_assert(!v == !has_out);
}

/*
 * This test verifies that we get EPOLLOUT from UDS sockets whenever the
 * outgoing queue runs *EMPTY*. That is, when we send data to a socket, we rely
 * on the kernel to re-notify us of EPOLLOUT whenever the other side cleared
 * its incoming queue.
 *
 * Additionally, we do the same test *after* we shutdown both read and write
 * side of the connection. That is, even if both channels are down and EPOLLHUP
 * is signalled, we still want to be notified of queues running empty.
 *
 * Both of these invariants is relied on by our socket implementation for
 * accounting reasons. Hence, they better be granted by the kernel.
 */
static void test_uds_edge(unsigned int run) {
        _c_cleanup_(dispatch_context_deinit) DispatchContext c = DISPATCH_CONTEXT_NULL(c);
        DispatchFile f = DISPATCH_FILE_NULL(f);
        char b[] = { "foobar" };
        int r, s[2];

        /* setup */

        r = dispatch_context_init(&c);
        c_assert(!r);

        r = socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, s);
        c_assert(!r);

        r = dispatch_file_init(&f, &c, NULL, s[0], EPOLLOUT, 0);
        c_assert(!r);

        dispatch_file_select(&f, EPOLLOUT);

        /* both queues empty, EPOLLOUT ready */

        q_assert(s[0], false, false);
        q_assert(s[1], false, false);

        r = dispatch_context_poll(&c, 0);
        c_assert(!r);
        c_assert(c_list_is_linked(&f.ready_link) && (f.events & EPOLLOUT));

        /* send message and verify sockets signal data */

        r = send(s[0], b, sizeof(b), MSG_DONTWAIT | MSG_NOSIGNAL);
        c_assert(r == sizeof(b));

        q_assert(s[0], false, true);
        q_assert(s[1], true, false);

        r = dispatch_context_poll(&c, 0);
        c_assert(!r);
        c_assert(c_list_is_linked(&f.ready_link) && (f.events & EPOLLOUT));

        /* clear EPOLLOUT (but keep it selected), verify it is not signalled */

        dispatch_file_clear(&f, EPOLLOUT);

        r = dispatch_context_poll(&c, 0);
        c_assert(!r);
        c_assert(!c_list_is_linked(&f.ready_link) && !(f.events & EPOLLOUT));

        /* receive data and verify socket becomes pollable */

        r = recv(s[1], b, sizeof(b), MSG_DONTWAIT);
        c_assert(r == sizeof(b));

        q_assert(s[0], false, false);
        q_assert(s[1], false, false);

        r = dispatch_context_poll(&c, 0);
        c_assert(!r);
        c_assert(c_list_is_linked(&f.ready_link) && (f.events & EPOLLOUT));

        /*
         * The first test succeeded. We now repeat this test, but before
         * dequeuing the data, we shutdown the socket.
         *
         * This simulates a server queueing data on a client that now decided
         * to disconnect. We want the server to be able to keep the connection
         * up and running, and still be notified of events, even though it was
         * shutdown. That is, we want to be notified of the queue running
         * empty, either via following recv(2) calls or a teardown of the
         * remote socket via the last close(2) call.
         */

        /* send message again and verify sockets signal data */

        r = send(s[0], b, sizeof(b), MSG_DONTWAIT | MSG_NOSIGNAL);
        c_assert(r == sizeof(b));

        q_assert(s[0], false, true);
        q_assert(s[1], true, false);

        r = dispatch_context_poll(&c, 0);
        c_assert(!r);
        c_assert(c_list_is_linked(&f.ready_link) && (f.events & EPOLLOUT));

        /* clear EPOLLOUT (but keep it selected), verify it is not signalled */

        dispatch_file_clear(&f, EPOLLOUT);

        r = dispatch_context_poll(&c, 0);
        c_assert(!r);
        c_assert(!c_list_is_linked(&f.ready_link) && !(f.events & EPOLLOUT));

        /* trigger remote shutdown and verify queue state did not change */

        r = shutdown(s[1], SHUT_RDWR);
        c_assert(!r);

        q_assert(s[0], false, true);
        q_assert(s[1], true, false);

        /*
         * Verify that EPOLLHUP is set. We do *NOT* use the dispatcher for
         * that. We want to make sure we are woken up for EPOLLOUT, not
         * EPOLLHUP, hence we better not select EPOLLHUP in the epoll-set. This
         * tests a fast-path the socket-layer uses to pass events to epoll
         * without requiring a callback into ->poll(). Furthermore, epoll
         * correctly ignores wake-ups for anything that does not provide our
         * events.
         * This is in no way a reliable way to just get woken up for EPOLLOUT.
         * But it decreases false-positives, so lets do it nevertheless.
         *
         * Note that we fetch EPOLLOUT here, since shutdown(2) might trigger
         * it. However, we explicitly clear is and fetch events again,
         * verifying we're no longer woken up for it.
         */

        r = send(s[0], b, sizeof(b), MSG_DONTWAIT | MSG_NOSIGNAL);
        c_assert(r < 0 && errno == EPIPE);

        /* fetch EPOLLOUT which was set by shutdown(2) and clear it */

        r = dispatch_context_poll(&c, 0);
        c_assert(!r);
        c_assert(c_list_is_linked(&f.ready_link) && (f.events & EPOLLOUT));

        dispatch_file_clear(&f, EPOLLOUT);

        r = dispatch_context_poll(&c, 0);
        c_assert(!r);
        c_assert(!(f.events & EPOLLOUT));

        /* receive data and verify socket becomes pollable */

        switch (run) {
        case 0:
                /* if @run is 0, we use recv(2) to dequeue data */
                r = recv(s[1], b, sizeof(b), MSG_DONTWAIT);
                c_assert(r == sizeof(b));

                q_assert(s[0], false, false);
                q_assert(s[1], false, false);
                break;
        case 1:
                /* if @run is 1, we use close(2) to flush queues */
                r = close(s[1]);
                c_assert(!r);
                s[1] = -1;

                q_assert(s[0], false, false);
                /* s[1] is obviously invalid here */
                break;
        default:
                c_assert(0);
        }

        r = dispatch_context_poll(&c, 0);
        c_assert(!r);
        c_assert(c_list_is_linked(&f.ready_link) && (f.events & EPOLLOUT));

        /* cleanup */

        dispatch_file_deinit(&f);
        c_close(s[1]);
        c_close(s[0]);
}

int main(int argc, char **argv) {
        test_uds_edge(0);
        test_uds_edge(1);
        return 0;
}
