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

static inline uint64_t nsec_from_clock(clockid_t clock) {
        struct timespec ts;
        int r;

        r = clock_gettime(clock, &ts);
        assert(r >= 0);
        return ts.tv_sec * UINT64_C(1000 * 1000 * 1000) + ts.tv_nsec;
}

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

static void *test_run_server(void *userdata) {
        sd_bus *bus = userdata;
        _c_cleanup_(sd_event_unrefp) sd_event *event = NULL;
        sigset_t mask_old, mask_new;
        int r;

        sigemptyset(&mask_new);
        sigaddset(&mask_new, SIGTERM);
        sigaddset(&mask_new, SIGINT);
        sigprocmask(SIG_BLOCK, &mask_new, &mask_old);

        r = sd_event_default(&event);
        assert(r >= 0);

        r = sd_event_add_signal(event, NULL, SIGTERM, NULL, NULL);
        assert(r >= 0);

        r = sd_event_add_signal(event, NULL, SIGINT, NULL, NULL);
        assert(r >= 0);

        r = sd_bus_attach_event(bus, event, SD_EVENT_PRIORITY_NORMAL);
        assert(r >= 0);

        r = sd_event_loop(event);
        assert(r >= 0);

        sigprocmask(SIG_SETMASK, &mask_old, NULL);

        return NULL;
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
        assert(strcmp(unique_name1, ":1.1") == 0);
        r = sd_bus_get_bus_id(bus1, &bus_id1);
        assert(r >= 0);

        r = sd_bus_get_unique_name(bus2, &unique_name2);
        assert(r >= 0);
        assert(strcmp(unique_name2, ":1.2") == 0);
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

static void test_connect(struct sockaddr_un *address, socklen_t addrlen, size_t iterations) {
        uint64_t start_time, end_time;
        int r;

        start_time = nsec_from_clock(CLOCK_MONOTONIC);
        for (size_t i = 0; i < iterations; i++) {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                const char *unique_name;

                bus = connect_bus(address, addrlen);
                r = sd_bus_get_unique_name(bus, &unique_name);
                assert(r >= 0);
        }
        end_time = nsec_from_clock(CLOCK_MONOTONIC);

        fprintf(stderr, "    connect/disconnect: %"PRIu64" us\n", (end_time - start_time) / iterations / 1000);
}

static void test_ping(struct sockaddr_un *address, socklen_t addrlen, const char *name, size_t iterations) {
        _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *client = NULL;
        uint64_t start_time, end_time;
        int r;

        client = connect_bus(address, addrlen);

        start_time = nsec_from_clock(CLOCK_MONOTONIC);
        for (size_t i = 0; i < iterations; i++) {
                _c_cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;

                r = sd_bus_call_method(client, name, "/org/freedesktop/DBus", "org.freedesktop.DBus.Peer", "Ping", NULL, &reply, "");
                assert(r >= 0);
                assert(reply);
        }
        end_time = nsec_from_clock(CLOCK_MONOTONIC);

        fprintf(stderr, "    ping/pong: %"PRIu64" us\n", (end_time - start_time) / iterations / 1000);
}

static void test_ping_peer_to_peer(size_t iterations) {
        _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *server = NULL, *client = NULL;
        int pair[2];
        sd_id128_t server_id = SD_ID128_NULL;
        uint64_t start_time, end_time;
        pthread_t thread;
        int r;

        r = socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, pair);
        assert(r >= 0);

        r = sd_bus_new(&server);
        assert(r >= 0);

        r = sd_bus_set_fd(server, pair[0], pair[0]);
        assert(r >= 0);

        r = sd_bus_set_server(server, true, server_id);
        assert(r >= 0);

        r = sd_bus_start(server);
        assert(r >= 0);

        r = pthread_create(&thread, NULL, test_run_server, server);
        assert(r == 0);

        r = sd_bus_new(&client);
        assert(r >= 0);

        r = sd_bus_set_fd(client, pair[1], pair[1]);
        assert(r >= 0);

        r = sd_bus_start(client);
        assert(r >= 0);

        start_time = nsec_from_clock(CLOCK_MONOTONIC);
        for (size_t i = 0; i < iterations; i++) {
                _c_cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;

                r = sd_bus_call_method(client, NULL, "/org/freedesktop/DBus", "org.freedesktop.DBus.Peer", "Ping", NULL, &reply, "");
                assert(r >= 0);
                assert(reply);
        }
        end_time = nsec_from_clock(CLOCK_MONOTONIC);

        r = pthread_kill(thread, SIGTERM);
        assert(r == 0);

        r = pthread_join(thread, NULL);
        assert(r == 0);

        fprintf(stderr, "    ping/pong: %"PRIu64" us\n", (end_time - start_time) / iterations / 1000);
}

static void tests(struct sockaddr_un *address, socklen_t addrlen) {
        _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *server = NULL;
        const char *unique_name;
        pthread_t thread;
        int r;

        server = connect_bus(address, addrlen);

        r = sd_bus_get_unique_name(server, &unique_name);
        assert(r >= 0);

        r = pthread_create(&thread, NULL, test_run_server, server);
        assert(r == 0);

        test_setup(address, addrlen);
        test_driver(address, addrlen);
        test_connect(address, addrlen, 1000);
        test_ping(address, addrlen, unique_name, 1000);

        r = pthread_kill(thread, SIGTERM);
        assert(r == 0);

        r = pthread_join(thread, NULL);
        assert(r == 0);
}

int main(int argc, char **argv) {
        struct sockaddr_un address;
        socklen_t addrlen;
        pthread_t thread;
        pid_t pid;
        int r;

        fprintf(stderr, " -- Peer-to-Peer --\n");
        test_ping_peer_to_peer(1000);

        fprintf(stderr, " -- Broker --\n");
        thread = test_spawn_broker(&address, &addrlen);

        tests(&address, addrlen);

        r = pthread_kill(thread, SIGTERM);
        assert(r == 0);

        r = pthread_join(thread, NULL);
        assert(r == 0);

        fprintf(stderr, " -- Daemon --\n");
        pid = test_spawn_daemon(&address, &addrlen);

        tests(&address, addrlen);

        r = kill(pid, SIGTERM);
        assert(r >= 0);

        pid = waitpid(pid, NULL, 0);
        assert(pid > 0);

        return 0;
}
