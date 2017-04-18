/*
 * Test D-Bus Socket Abstraction
 */

#include <c-macro.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "message.h"
#include "socket.h"

static void test_setup(void) {
        _c_cleanup_(socket_freep) Socket *server = NULL, *client = NULL;
        int r;

        r = socket_new(&server, -1, true);
        assert(r >= 0);

        r = socket_new(&client, -1, false);
        assert(r >= 0);
}

static void test_line(void) {
        _c_cleanup_(socket_freep) Socket *client = NULL, *server = NULL;
        char *test = "TEST\r\n";
        char *line;
        size_t *pos, n_bytes;
        int pair[2], r;

        r = socketpair(AF_UNIX, SOCK_STREAM, 0, pair);
        assert(r >= 0);

        r = socket_new(&client, pair[0], false);
        assert(r >= 0);

        r = socket_new(&server, pair[1], true);
        assert(r >= 0);

        r = socket_read_line(server, &line, &n_bytes);
        assert(r == -EAGAIN);

        r = socket_queue_line(client, 16, &line, &pos);
        assert(r >= 0);

        memcpy(line, test, strlen(test));
        *pos += strlen(test);

        r = socket_queue_line(client, 16, &line, &pos);
        assert(r >= 0);

        memcpy(line, test, strlen(test));
        *pos += strlen(test);

        r = socket_write(client);
        assert(r >= 0);

        r = socket_read_line(server, &line, &n_bytes);
        assert(r >= 0);
        assert(n_bytes == strlen(test) - 2);
        assert(memcmp(test, line, n_bytes) == 0);

        r = socket_read_line(server, &line, &n_bytes);
        assert(r >= 0);
        assert(n_bytes == strlen(test) - 2);
        assert(memcmp(test, line, n_bytes) == 0);

        r = socket_read_line(server, &line, &n_bytes);
        assert(r == -EAGAIN);
}

static void test_message(void) {
        _c_cleanup_(socket_freep) Socket *client = NULL, *server = NULL;
        _c_cleanup_(message_unrefp) Message *message1 = NULL, *message2 = NULL;
        MessageHeader header = {
                .endian = 'l',
        };
        int pair[2], r;

        r = socketpair(AF_UNIX, SOCK_STREAM, 0, pair);
        assert(r >= 0);

        r = socket_new(&client, pair[0], false);
        assert(r >= 0);

        r = socket_new(&server, pair[1], true);
        assert(r >= 0);

        r = socket_read_message(server, &message2);
        assert(r == -EAGAIN);

        r = message_new_incoming(&message1, header);
        assert(r >= 0);

        r = socket_queue_message(client, message1);
        assert(r >= 0);

        r = socket_write(client);
        assert(r >= 0);

        r = socket_read_message(server, &message2);
        assert(r >= 0);

        assert(memcmp(message1->header, message2->header, sizeof(header)) == 0);
}

int main(int argc, char **argv) {
        test_setup();
        test_line();
        test_message();
        return 0;
}
