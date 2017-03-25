/*
 * Test D-Bus Socket Abstraction
 */

#include <c-macro.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "dbus-message.h"
#include "dbus-socket.h"

static void test_setup(void) {
        _c_cleanup_(dbus_socket_freep) DBusSocket *socket = NULL;
        int r;

        r = dbus_socket_new(&socket, -1);
        assert(r >= 0);
}

static void test_line(void) {
        _c_cleanup_(dbus_socket_freep) DBusSocket *socket1 = NULL,
                                                  *socket2 = NULL;
        char *line;
        size_t *pos, n_bytes;
        int pair[2], r;

        r = socketpair(AF_UNIX, SOCK_STREAM, 0, pair);
        assert(r >= 0);

        r = dbus_socket_new(&socket1, pair[0]);
        assert(r >= 0);

        r = dbus_socket_new(&socket2, pair[1]);
        assert(r >= 0);

        r = dbus_socket_read_line(socket1, &line, &n_bytes);
        assert(r == -EAGAIN);

        r = dbus_socket_reserve_line(socket1, 16, &line, &pos);
        assert(r >= 0);

        memcpy(line, "\0TEST", 1 + strlen("TEST"));
        *pos += 1 + strlen("TEST");
}

static void test_message(void) {
        _c_cleanup_(dbus_socket_freep) DBusSocket *socket1 = NULL,
                                                  *socket2 = NULL;
        _c_cleanup_(dbus_message_unrefp) DBusMessage *message = NULL;
        DBusMessageHeader header = {
                .endian = 'l',
        };
        int pair[2], r;

        r = socketpair(AF_UNIX, SOCK_STREAM, 0, pair);
        assert(r >= 0);

        r = dbus_socket_new(&socket1, pair[0]);
        assert(r >= 0);

        r = dbus_socket_new(&socket2, pair[1]);
        assert(r >= 0);

        r = dbus_socket_read_message(socket1, &message);
        assert(r == -EAGAIN);

        r = dbus_message_new(&message, header);
        assert(r >= 0);

        r = dbus_socket_queue_message(socket1, message);
        assert(r >= 0);
}

int main(int argc, char **argv) {
        test_setup();
        test_line();
        test_message();
        return 0;
}
