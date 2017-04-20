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
        _c_cleanup_(sd_bus_message_unrefp) sd_bus_message *message1 = NULL, *message2 = NULL;
        const char *unique_name1, *unique_name2;
        sd_id128_t bus_id1, bus_id2;
        uint64_t cookie1, cookie2;
        uint8_t type;
        struct sockaddr_un address;
        socklen_t addrlen;
        pthread_t thread;
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

        r = sd_bus_message_new_method_call(bus1, &message1, unique_name2, "/", "org.freedesktop.DBus", "Ping");
        assert(r >= 0);

        r = sd_bus_send(bus1, message1, &cookie1);
        assert(r >= 0);

        r = sd_bus_wait(bus2, -1);
        assert(r == 1);

        r = sd_bus_process(bus2, &message2);
        assert(r > 0);

        r = sd_bus_message_get_type(message2, &type);
        assert(r >= 0);
        assert(type == SD_BUS_MESSAGE_SIGNAL);

        r = sd_bus_message_get_cookie(message2, &cookie2);
        assert(r >= 0);
        assert(cookie2 == (uint32_t)-1);

        sd_bus_message_unref(message2);

        r = sd_bus_wait(bus2, -1);
        assert(r == 1);

        r = sd_bus_process(bus2, &message2);
        assert(r > 0);

        r = sd_bus_message_get_type(message2, &type);
        assert(r >= 0);
        assert(type == SD_BUS_MESSAGE_METHOD_CALL);

        r = sd_bus_message_get_cookie(message2, &cookie2);
        assert(r >= 0);
        assert(cookie2 == cookie1);

        r = pthread_kill(thread, SIGTERM);
        assert(r == 0);

        r = pthread_join(thread, NULL);
        assert(r == 0);
}

int main(int argc, char **argv) {
        test_setup();
        return 0;
}
