/*
 * Test D-Bus Socket Abstraction
 */

#undef NDEBUG
#include <c-stdaux.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "dbus/message.h"
#include "dbus/socket.h"

static void test_setup(void) {
        _c_cleanup_(socket_deinit) Socket server = SOCKET_NULL(server), client = SOCKET_NULL(client);

        socket_init(&server, NULL, -1);
        socket_init(&client, NULL, -1);
}

static void test_line(void) {
        _c_cleanup_(socket_deinit) Socket client = SOCKET_NULL(client), server = SOCKET_NULL(server);
        const char *test = "TEST", *line;
        size_t n_bytes;
        int pair[2], r;

        r = socketpair(AF_UNIX, SOCK_STREAM, 0, pair);
        c_assert(r >= 0);

        socket_init(&client, NULL, pair[0]);
        socket_init(&server, NULL, pair[1]);

        r = socket_dequeue_line(&server, &line, &n_bytes);
        c_assert(!r && !line);

        r = socket_queue_line(&client, NULL, test, strlen(test));
        c_assert(r == 0);

        r = socket_queue_line(&client, NULL, test, strlen(test));
        c_assert(r == 0);

        r = socket_dispatch(&client, EPOLLOUT);
        c_assert(r == SOCKET_E_LOST_INTEREST);
        r = socket_dispatch(&server, EPOLLIN);
        c_assert(!r || r == SOCKET_E_PREEMPTED);

        r = socket_dequeue_line(&server, &line, &n_bytes);
        c_assert(!r && line);
        c_assert(n_bytes == strlen(test));
        c_assert(memcmp(test, line, n_bytes) == 0);

        r = socket_dequeue_line(&server, &line, &n_bytes);
        c_assert(!r && line);
        c_assert(n_bytes == strlen(test));
        c_assert(memcmp(test, line, n_bytes) == 0);

        r = socket_dequeue_line(&server, &line, &n_bytes);
        c_assert(!r && !line);
}

static void test_message(void) {
        _c_cleanup_(socket_deinit) Socket client = SOCKET_NULL(client), server = SOCKET_NULL(server);
        _c_cleanup_(message_unrefp) Message *message1 = NULL, *message2 = NULL;
        MessageHeader header = {
                .endian = 'l',
        };
        int pair[2], r;

        r = socketpair(AF_UNIX, SOCK_STREAM, 0, pair);
        c_assert(r >= 0);

        socket_init(&client, NULL, pair[0]);
        socket_init(&server, NULL, pair[1]);

        r = socket_dequeue(&server, &message2);
        c_assert(!r && !message2);

        r = message_new_incoming(&message1, header);
        c_assert(r == 0);

        r = socket_queue(&client, NULL, message1);
        c_assert(!r);

        r = socket_dispatch(&client, EPOLLOUT);
        c_assert(r == SOCKET_E_LOST_INTEREST);
        r = socket_dispatch(&server, EPOLLIN);
        c_assert(!r || r == SOCKET_E_PREEMPTED);

        r = socket_dequeue(&server, &message2);
        c_assert(!r && message2);

        c_assert(memcmp(message1->header, message2->header, sizeof(header)) == 0);
}

int main(int argc, char **argv) {
        test_setup();
        test_line();
        test_message();
        return 0;
}
