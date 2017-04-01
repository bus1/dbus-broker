/*
 * Test Broker
 */

#include <c-macro.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <systemd/sd-bus.h>
#include "test.h"

static void test_setup(void) {
        _c_cleanup_(sd_bus_unrefp) sd_bus *bus = NULL;
        struct sockaddr_un address;
        socklen_t addrlen;
        int r, fd;

        spawn_bus(&address, &addrlen);

        fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        assert(fd >= 0);

        r = connect(fd, (struct sockaddr*)&address, addrlen);
        assert(r >= 0);

        r = sd_bus_new(&bus);
        assert(r >= 0);

        r = sd_bus_set_fd(bus, fd, fd);
        assert(r >= 0);

        r = sd_bus_start(bus);
        assert(r >= 0);

        for (;;) {
                r = sd_bus_process(bus, NULL);
                if (r > 0)
                        continue;
                assert(r == 0);

                r = sd_bus_wait(bus, -1);
                assert(r >= 0);
        }
}

int main(int argc, char **argv) {
        test_setup();
        return 0;
}
