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

static void test_driver_names(struct sockaddr_un *address, socklen_t addrlen) {
        _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus1 = NULL, *bus2 = NULL;
        sd_bus_message *message = NULL, *reply = NULL;
        sd_bus_error error = SD_BUS_ERROR_NULL;
        const char *unique_name1, *unique_name2, *reply_string;
        uint32_t reply_u32;
        int r;

        bus1 = connect_bus(address, addrlen);
        bus2 = connect_bus(address, addrlen);

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

static void test_driver_hello(struct sockaddr_un *address, socklen_t addrlen) {
        _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        sd_bus_error error = SD_BUS_ERROR_NULL;
        const char *unique_name;
        int r;

        fprintf(stderr, " - Hello()\n");

        bus = connect_bus(address, addrlen);

        /* Hello() has already been called, just verify that we have received the correct unique name */
        r = sd_bus_get_unique_name(bus, &unique_name);
        assert(r >= 0);
        assert(!strcmp(unique_name, ":1.1"));

        /* Calling Hello() again should fail with error "Failed" */
        r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "Hello", &error, NULL,
                               "");
        assert(r < 0);
        assert(!strcmp(error.name, "org.freedesktop.DBus.Error.Failed"));
        sd_bus_error_free(&error);
}

static void test_driver_request_name(struct sockaddr_un *address, socklen_t addrlen) {
        _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        sd_bus_error error = SD_BUS_ERROR_NULL;
        const char *unique_name;
        int r;

        fprintf(stderr, " - RequestName()\n");

        bus = connect_bus(address, addrlen);

        r = sd_bus_get_unique_name(bus, &unique_name);
        assert(r >= 0);

        /* XXX: check invalid flags */

        /* request a name */
        r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "RequestName", NULL, NULL,
                               "su", "com.example.foo", 0);
        assert(r >= 0);

        /* request a reserved name */
        r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "RequestName", &error, NULL,
                               "su", "org.freedesktop.DBus", 0);
        assert(r < 0);
        assert(!strcmp(error.name, "org.freedesktop.DBus.Error.InvalidArgs"));
        sd_bus_error_free(&error);

        /* request our own unique name */
        r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "RequestName", &error, NULL,
                               "su", unique_name, 0);
        assert(r < 0);
        assert(!strcmp(error.name, "org.freedesktop.DBus.Error.InvalidArgs"));
        sd_bus_error_free(&error);

        /* XXX: test invalid name */

        /* clean up the name */
        r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "ReleaseName", NULL, NULL,
                               "s", "com.example.foo");
        assert(r >= 0);
}

static void test_driver_release_name(struct sockaddr_un *address, socklen_t addrlen) {
        _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        sd_bus_error error = SD_BUS_ERROR_NULL;
        const char *unique_name;
        int r;

        fprintf(stderr, " - ReleaseName()\n");

        bus = connect_bus(address, addrlen);

        r = sd_bus_get_unique_name(bus, &unique_name);
        assert(r >= 0);

        /* request a name */
        r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "RequestName", NULL, NULL,
                               "su", "com.example.foo", 0);
        assert(r >= 0);

        /* release the name */
        r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "ReleaseName", NULL, NULL,
                               "s", "com.example.foo");
        assert(r >= 0);

        /* releaese a reserved name */
        r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "ReleaseName", &error, NULL,
                               "s", "org.freedesktop.DBus");
        assert(r < 0);
        assert(!strcmp(error.name, "org.freedesktop.DBus.Error.InvalidArgs"));
        sd_bus_error_free(&error);

        /* release our unique name */
        r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "ReleaseName", &error, NULL,
                               "s", unique_name);
        assert(r < 0);
        assert(!strcmp(error.name, "org.freedesktop.DBus.Error.InvalidArgs"));
        sd_bus_error_free(&error);

        /* XXX: test invalid name */
}

static void test_driver_get_name_owner(struct sockaddr_un *address, socklen_t addrlen) {
        _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        sd_bus_message *reply = NULL;
        sd_bus_error error = SD_BUS_ERROR_NULL;
        const char *unique_name, *owner;
        int r;

        fprintf(stderr, " - GetNameOwner()\n");

        bus = connect_bus(address, addrlen);

        r = sd_bus_get_unique_name(bus, &unique_name);
        assert(r >= 0);

        /* request a name */
        r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "RequestName", NULL, NULL,
                               "su", "com.example.foo", 0);
        assert(r >= 0);

        /* get the owner */
        r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "GetNameOwner", NULL, &reply,
                               "s", "com.example.foo");
        assert(r >= 0);
        r = sd_bus_message_read(reply, "s", &owner);
        assert(r >= 0);
        assert(!strcmp(owner, unique_name));
        sd_bus_message_unref(reply);

        /* get the owner of our unique name */
        r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "GetNameOwner", NULL, &reply,
                               "s", unique_name);
        assert(r >= 0);
        r = sd_bus_message_read(reply, "s", &owner);
        assert(r >= 0);
        assert(!strcmp(owner, unique_name));
        sd_bus_message_unref(reply);

        /* get the owner of the driver */
        r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "GetNameOwner", NULL, &reply,
                               "s", "org.freedesktop.DBus");
        assert(r >= 0);
        r = sd_bus_message_read(reply, "s", &owner);
        assert(r >= 0);
        assert(!strcmp(owner, "org.freedesktop.DBus"));
        sd_bus_message_unref(reply);

        /* get the owner of a name that does not exist */
        r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "GetNameOwner", &error, NULL,
                               "s", "com.example.bar");
        assert(r < 0);
        assert(!strcmp(error.name, "org.freedesktop.DBus.Error.NameHasNoOwner"));
        sd_bus_error_free(&error);

        /* XXX: test invalid name */

        /* clean up the name */
        r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "ReleaseName", NULL, NULL,
                               "s", "com.example.foo");
        assert(r >= 0);
}

static void test_driver_name_has_owner(struct sockaddr_un *address, socklen_t addrlen) {
        _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        sd_bus_message *reply = NULL;
        const char *unique_name;
        int r, owned;

        fprintf(stderr, " - NameHasOwner()\n");

        bus = connect_bus(address, addrlen);

        r = sd_bus_get_unique_name(bus, &unique_name);
        assert(r >= 0);

        /* request a name */
        r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "RequestName", NULL, NULL,
                               "su", "com.example.foo", 0);
        assert(r >= 0);

        /* check if owned */
        r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "NameHasOwner", NULL, &reply,
                               "s", "com.example.foo");
        assert(r >= 0);
        r = sd_bus_message_read(reply, "b", &owned);
        assert(r >= 0);
        assert(owned);
        sd_bus_message_unref(reply);

        /* check if unique name is owned */
        r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "NameHasOwner", NULL, &reply,
                               "s", unique_name);
        assert(r >= 0);
        r = sd_bus_message_read(reply, "b", &owned);
        assert(r >= 0);
        assert(owned);
        sd_bus_message_unref(reply);

        /* check if driver is owned */
        r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "NameHasOwner", NULL, &reply,
                               "s", "org.freedesktop.DBus");
        assert(r >= 0);
        r = sd_bus_message_read(reply, "b", &owned);
        assert(r >= 0);
        assert(owned);
        sd_bus_message_unref(reply);

        /* check if non-existent name has owner */
        r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "NameHasOwner", NULL, &reply,
                               "s", "com.example.bar");
        assert(r >= 0);
        r = sd_bus_message_read(reply, "b", &owned);
        assert(r >= 0);
        assert(!owned);
        sd_bus_message_unref(reply);

        /* XXX: test invalid name */
}
static void test_driver_api(struct sockaddr_un *address, socklen_t addrlen) {
        _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int r;

        test_driver_hello(address, addrlen);
        test_driver_request_name(address, addrlen);
        test_driver_release_name(address, addrlen);
        test_driver_get_name_owner(address, addrlen);
        test_driver_name_has_owner(address, addrlen);

        bus = connect_bus(address, addrlen);

        r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "RequestName", NULL, NULL,
                               "su", "com.example.baz", 0);
        assert(r >= 0);

        r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "ListNames", NULL, NULL,
                               "");
        assert(r >= 0);

        r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "ListActivatableNames", NULL, NULL,
                               "");
        assert(r >= 0);

        r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "ListQueuedOwners", NULL, NULL,
                               "s", "com.example.baz");
        assert(r >= 0);

        r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "GetAdtAuditSessionData", NULL, NULL,
                               "s", "com.example.baz");
        assert(r < 0);

        r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "GetConnectionCredentials", NULL, NULL,
                               "s", "com.example.baz");
        assert(r >= 0);

        r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "GetConnectionSELinuxSecurityContext", NULL, NULL,
                               "s", "com.example.baz");
        /* this will fail or succeed depending on whether or not SELinux is enabled */

        r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "GetConnectionUnixProcessID", NULL, NULL,
                               "s", "com.example.baz");
        assert(r >= 0);

        r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "GetConnectionUnixUser", NULL, NULL,
                               "s", "com.example.baz");
        assert(r >= 0);

        r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "AddMatch", NULL, NULL,
                               "s", "sender=org.freedesktop.DBus");
        assert(r >= 0);

        r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "RemoveMatch", NULL, NULL,
                               "s", "sender=org.freedesktop.DBus");
        assert(r >= 0);

        r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "GetId", NULL, NULL,
                               "");
        assert(r >= 0);

        r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "StartServiceByName", NULL, NULL,
                               "su", "com.example.baz", 0);
        assert(r < 0);

        r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "ReleaseName", NULL, NULL,
                               "s", "com.example.baz");
        assert(r >= 0);

        r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "UpdateActivationEnvironment", NULL, NULL,
                               "a{ss}", 0);
        assert(r >= 0);

        r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus.Introspectable",
                               "Introspect", NULL, NULL,
                               "");
        assert(r >= 0);

        r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus.Monitoring",
                               "BecomeMonitor", NULL, NULL,
                               "asu", 0, 0);
        assert(r >= 0);

        /* calling any method after having become monitor forcibly disconnects the peer */
        r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "Hello", NULL, NULL,
                               "");
        assert(r < 0);
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

        test_driver_api(address, addrlen);
        test_driver_names(address, addrlen);

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

        /* broker */
        fprintf(stderr, "BROKER\n");
        thread = test_spawn_broker(&address, &addrlen);

        tests(&address, addrlen);

        r = pthread_kill(thread, SIGTERM);
        assert(r == 0);

        r = pthread_join(thread, NULL);
        assert(r == 0);

        /* daemon */
        fprintf(stderr, "DAEMON\n");
        pid = test_spawn_daemon(&address, &addrlen);

        tests(&address, addrlen);

        r = kill(pid, SIGTERM);
        assert(r >= 0);

        pid = waitpid(pid, NULL, 0);
        assert(pid > 0);

        return 0;
}
