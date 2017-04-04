/*
 * Test Dispatcher
 */

#include <c-macro.h>
#include <linux/sockios.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include "dispatch.h"

static void q_assert(int s, bool has_in, bool has_out) {
        int r, v;

        /*
         * Verify that the IN/OUT queues are (non-)empty, depending on what is
         * given as @has_in and @has_out.
         */

        r = ioctl(s, SIOCINQ, &v);
        assert(r >= 0);
        assert(!v == !has_in);

        r = ioctl(s, SIOCOUTQ, &v);
        assert(r >= 0);
        assert(!v == !has_out);
}

/*
 * This test verifies that we get EPOLLOUT from UDS sockets whenever the
 * outgoing queue runs *EMPTY*. That is, when we send data to a socket, we rely
 * on the kernel to re-notify us of EPOLLOUT whenever the other side cleared
 * its incoming queue.
 */
static void test_uds_edge(void) {
        _c_cleanup_(dispatch_context_deinit) DispatchContext c = DISPATCH_CONTEXT_NULL;
        DispatchFile f = DISPATCH_FILE_NULL(f);
        CList l = C_LIST_INIT(l);
        char b;
        int r, s[2];

        /* setup */

        r = dispatch_context_init(&c);
        assert(!r);

        r = socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, s);
        assert(!r);

        r = dispatch_file_init(&f, &c, &l, NULL, s[0], EPOLLOUT);
        assert(!r);

        dispatch_file_select(&f, EPOLLOUT);

        /* both queues empty, EPOLLOUT ready */

        q_assert(s[0], false, false);
        q_assert(s[1], false, false);

        r = dispatch_context_poll(&c, 0);
        assert(!r);
        assert(c_list_is_linked(&f.ready_link) && (f.events & EPOLLOUT));

        /* send message and verify sockets signal data */

        r = send(s[0], "foobar", 6, MSG_DONTWAIT | MSG_NOSIGNAL);
        assert(r == 6);

        q_assert(s[0], false, true);
        q_assert(s[1], true, false);

        r = dispatch_context_poll(&c, 0);
        assert(!r);
        assert(c_list_is_linked(&f.ready_link) && (f.events & EPOLLOUT));

        /* clear EPOLLOUT (but keep it selected), verify it is not signalled */

        dispatch_file_clear(&f, EPOLLOUT);

        r = dispatch_context_poll(&c, 0);
        assert(!r);
        assert(!c_list_is_linked(&f.ready_link) && !(f.events & EPOLLOUT));

        /* receive data and verify socket becomes pollable */

        r = recv(s[1], &b, 6, MSG_DONTWAIT);
        assert(r == 6);

        q_assert(s[0], false, false);
        q_assert(s[1], false, false);

        r = dispatch_context_poll(&c, 0);
        assert(!r);
        assert((f.events & EPOLLOUT));
        assert(c_list_is_linked(&f.ready_link) && (f.events & EPOLLOUT));

        /* cleanup */

        dispatch_file_deinit(&f);
        close(s[1]);
        close(s[0]);
}

int main(int argc, char **argv) {
        test_uds_edge();
        return 0;
}
