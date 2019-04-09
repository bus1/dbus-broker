/*
 * Flood destination with pings
 */

#undef NDEBUG
#include <c-stdaux.h>
#include <math.h>
#include <stdlib.h>
#include "util-broker.h"
#include "util-message.h"
#include "dbus/protocol.h"

static void test_connect_system_blocking_fd(int *fdp) {
        _c_cleanup_(c_closep) int fd = -1;
        _c_cleanup_(c_freep) void *hello = NULL;
        struct sockaddr_un addr = {};
        size_t n_hello = 0;
        uint8_t reply[316];
        ssize_t len;
        int r;

        test_message_append_sasl(&hello, &n_hello);
        test_message_append_hello(&hello, &n_hello);

        fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        assert(fd >= 0);

        addr.sun_family = AF_UNIX;
        strcpy(addr.sun_path, "/run/dbus/system_bus_socket");

        r = connect(fd, (struct sockaddr *)&addr, offsetof(struct sockaddr_un, sun_path) + strlen(addr.sun_path) + 1);
        assert(r >= 0);

        len = write(fd, hello, n_hello);
        assert(len == (ssize_t)n_hello);

        len = recv(fd, reply, sizeof(reply), MSG_WAITALL);
        assert(len == (ssize_t)sizeof(reply));

        *fdp = fd;
        fd = -1;
}

noreturn static void test_flood(const char *destination) {
        _c_cleanup_(c_closep) int fd = -1;
        uint32_t serial = 0;;

        test_connect_system_blocking_fd(&fd);

        for (;;) {
                _c_cleanup_(c_freep) void *ping = NULL;
                size_t n_ping = 0;
                ssize_t len;

                test_message_append_ping2(&ping, &n_ping, ++serial, NULL, destination);

                len = write(fd, ping, n_ping);
                assert(len == (ssize_t)n_ping);

                if (serial % 1000 == 0)
                        fprintf(stderr, "PING! (%"PRIu32")\n", serial);

                assert(serial);
        }
}

int main(int argc, char **argv) {
        assert(argc == 2);

        test_flood(argv[1]);
}
