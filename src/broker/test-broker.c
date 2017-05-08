/*
 * Test Broker
 */

#include <c-macro.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <systemd/sd-bus.h>
#include <systemd/sd-id128.h>
#include "dbus/protocol.h"
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

static void test_setup(struct sockaddr_un *address, socklen_t addrlen) {
        _c_cleanup_(sd_bus_unrefp) sd_bus *bus1 = NULL, *bus2 = NULL;
        _c_cleanup_(sd_bus_message_unrefp) sd_bus_message *message1 = NULL, *message2 = NULL;
        const char *unique_name1, *unique_name2;
        sd_id128_t bus_id1, bus_id2;
        uint64_t cookie1, cookie2;
        uint8_t type;
        int r;

        bus1 = connect_bus(address, addrlen);
        bus2 = connect_bus(address, addrlen);

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
        assert(cookie2 != 0); /* the broker sets -1, the daemon does not fix this */

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
}

static void test_driver_names(sd_bus *bus1, sd_bus *bus2) {
        sd_bus_message *message = NULL, *reply = NULL;
        sd_bus_error error = SD_BUS_ERROR_NULL;
        const char *unique_name1, *unique_name2, *reply_string;
        uint32_t reply_u32;
        int r;

        r = sd_bus_get_unique_name(bus1, &unique_name1);
        assert(r >= 0);

        r = sd_bus_get_unique_name(bus2, &unique_name2);
        assert(r >= 0);

        /* get the owner of a non-existent name */
        r = sd_bus_call_method(bus1, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "GetNameOwner", &error, &reply,
                               "s", "com.example.foobar");
        assert(r < 0);
        assert(strcmp(error.name, "org.freedesktop.DBus.Error.NameHasNoOwner") == 0);
        sd_bus_error_free(&error);

        /* grab a well-known name */
        r = sd_bus_call_method(bus1, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "RequestName", &error, &reply,
                               "su", "com.example.foobar", 0);
        assert(r >= 0);
        sd_bus_message_unref(message);

        r = sd_bus_message_read(reply, "u", &reply_u32);
        assert(r >= 0);
        assert(reply_u32 == DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER);
        sd_bus_message_unref(reply);

        /* check that we now own it */
        r = sd_bus_call_method(bus1, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "GetNameOwner", &error, &reply,
                               "s", "com.example.foobar");
        r = sd_bus_message_read(reply, "s", &reply_string);
        assert(r >= 0);
        assert(strcmp(reply_string, unique_name1) == 0);
        sd_bus_message_unref(reply);

        /* queue another owner request on the same name */
        r = sd_bus_call_method(bus2, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "RequestName", &error, &reply,
                               "su", "com.example.foobar", 0);
        assert(r >= 0);
        sd_bus_message_unref(message);

        r = sd_bus_message_read(reply, "u", &reply_u32);
        assert(r >= 0);
        assert(reply_u32 == DBUS_REQUEST_NAME_REPLY_IN_QUEUE);
        sd_bus_message_unref(reply);

        /* explicitly release the name as the primary owner */
        r = sd_bus_call_method(bus1, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "ReleaseName", &error, &reply,
                               "s", "com.example.foobar");
        assert(r >= 0);
        sd_bus_message_unref(message);

        r = sd_bus_message_read(reply, "u", &reply_u32);
        assert(r >= 0);
        assert(reply_u32 == DBUS_RELEASE_NAME_REPLY_RELEASED);
        sd_bus_message_unref(reply);
}

static void test_driver(struct sockaddr_un *address, socklen_t addrlen) {
        _c_cleanup_(sd_bus_unrefp) sd_bus *bus1 = NULL, *bus2 = NULL;

        bus1 = connect_bus(address, addrlen);
        bus2 = connect_bus(address, addrlen);

        test_driver_names(bus1, bus2);
}

int main(int argc, char **argv) {
        struct sockaddr_un address;
        socklen_t addrlen;
        pthread_t thread;
        pid_t pid;
        int r;

        /* broker */
        thread = test_spawn_broker(&address, &addrlen);

        test_setup(&address, addrlen);
        test_driver(&address, addrlen);

        r = pthread_kill(thread, SIGTERM);
        assert(r == 0);

        r = pthread_join(thread, NULL);
        assert(r == 0);

        /* daemon */
        pid = test_spawn_daemon(&address, &addrlen);

        test_setup(&address, addrlen);
        test_driver(&address, addrlen);

        r = kill(pid, SIGTERM);
        assert(r >= 0);

        pid = waitpid(pid, NULL, 0);
        assert(pid > 0);

        return 0;
}
