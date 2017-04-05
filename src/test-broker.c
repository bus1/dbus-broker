/*
 * Test Broker
 */

#include <c-macro.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <systemd/sd-bus.h>
#include <systemd/sd-id128.h>
#include "test.h"

static sd_bus *connect_bus(struct sockaddr_un *address, socklen_t addrlen) {
        sd_bus *bus;
        int fd, r;

        fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        assert(fd >= 0);

        r = connect(fd, (struct sockaddr*)address, addrlen);
        assert(r >= 0);

        r = sd_bus_new(&bus);
        assert(r >= 0);

        r = sd_bus_set_fd(bus, fd, fd);
        assert(r >= 0);

        r = sd_bus_set_bus_client(bus, true);
        assert(r >= 0);

        r = sd_bus_start(bus);
        assert(r >= 0);

        return bus;
}

static void test_setup(void) {
        _c_cleanup_(sd_bus_unrefp) sd_bus *bus1 = NULL, *bus2 = NULL;
        const char *unique_name1, *unique_name2;
        sd_id128_t bus_id1, bus_id2;
        struct sockaddr_un address;
        socklen_t addrlen;
        pthread_t thread;
        void *retval;
        int r;

        thread = test_spawn_bus(&address, &addrlen);

        bus1 = connect_bus(&address, addrlen);
        bus2 = connect_bus(&address, addrlen);

        r = sd_bus_get_unique_name(bus1, &unique_name1);
        assert(r >= 0);
        assert(strcmp(unique_name1, ":1.0") == 0);
        r = sd_bus_get_bus_id(bus1, &bus_id1);
        assert(r >= 0);

        r = sd_bus_get_unique_name(bus2, &unique_name2);
        assert(r >= 0);
        assert(strcmp(unique_name2, ":1.1") == 0);
        r = sd_bus_get_bus_id(bus2, &bus_id2);
        assert(r >= 0);
        assert(sd_id128_equal(bus_id1, bus_id2));

        r = pthread_cancel(thread);
        assert(r == 0);

        r = pthread_join(thread, &retval);
        assert(r == 0 && retval == PTHREAD_CANCELED);
}

int main(int argc, char **argv) {
        test_setup();
        return 0;
}
