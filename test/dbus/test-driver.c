/*
 * Basic Broker Driver API Tests
 */

#include <c-macro.h>
#include <stdlib.h>
#include "../../src/dbus/protocol.h"
#include "util-broker.h"

static void test_hello(void) {
        _c_cleanup_(util_broker_freep) Broker *broker = NULL;
        int r;

        util_broker_new(&broker);
        util_broker_spawn(broker);

        /* call Hello() twice, see that the first succeeds and the second fails */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                const char *unique_name = NULL;

                util_broker_connect_raw(broker, &bus);

                /* do the Hello() */
                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "Hello", NULL, &reply,
                                       "");

                r = sd_bus_message_read(reply, "s", &unique_name);
                assert(r >= 0);
                assert(!strcmp(unique_name, ":1.0"));

                /* calling Hello() again is not valid */
                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "Hello", &error, NULL,
                                       "");
                assert(r < 0);
                assert(!strcmp(error.name, "org.freedesktop.DBus.Error.Failed"));
        }

        /* call something else before Hello(), see that it fails and the client is disconnected */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                util_broker_connect_raw(broker, &bus);

                /* call something other than Hello() */
                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "RequestName", &error, NULL,
                                       "su", "com.example.foo", 0);
                assert(!strcmp(error.name, "org.freedesktop.DBus.Error.AccessDenied"));

                /* now try to call Hello() (or anything else), to verify that the client was disconnected */
                if (!getenv("DBUS_BROKER_TEST_DAEMON")) {
                        /* XXX: the dbus daemon does not work according to spec here, as far as I can tell, let's skip it for now */
                        r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                               "Hello", NULL, NULL,
                                               "");
                        assert(r == -ECONNRESET);
                }
        }

        util_broker_terminate(broker);
}

static void test_request_name(void) {
        _c_cleanup_(util_broker_freep) Broker *broker = NULL;
        int r;

        util_broker_new(&broker);
        util_broker_spawn(broker);

        /* XXX: test invalid flags? */

        /* request valid well-known name and release it again */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
                const char *unique_name, *owner;

                util_broker_connect(broker, &bus);

                r = sd_bus_get_unique_name(bus, &unique_name);
                assert(r >= 0);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "RequestName", NULL, NULL,
                                       "su", "com.example.foo", 0);
                assert(r >= 0);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "GetNameOwner", NULL, &reply,
                                       "s", "com.example.foo");
                assert(r >= 0);
                r = sd_bus_message_read(reply, "s", &owner);
                assert(r >= 0);
                assert(!strcmp(owner, unique_name));

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "ReleaseName", NULL, NULL,
                                       "s", "com.example.foo");
                assert(r >= 0);
        }

        /* request currently owned name and replace its owner */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus1 = NULL, *bus2 = NULL;
                _c_cleanup_(sd_bus_message_unrefp) sd_bus_message *reply1 = NULL, *reply2 = NULL;
                const char *unique_name1, *unique_name2, *owner;

                util_broker_connect(broker, &bus1);
                util_broker_connect(broker, &bus2);

                r = sd_bus_get_unique_name(bus1, &unique_name1);
                r = sd_bus_get_unique_name(bus2, &unique_name2);

                r = sd_bus_call_method(bus1, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "RequestName", NULL, NULL,
                                       "su", "com.example.foo", DBUS_NAME_FLAG_ALLOW_REPLACEMENT);
                assert(r >= 0);

                r = sd_bus_call_method(bus2, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "RequestName", NULL, NULL,
                                       "su", "com.example.foo", DBUS_NAME_FLAG_REPLACE_EXISTING);
                assert(r >= 0);

                r = sd_bus_call_method(bus2, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "GetNameOwner", NULL, &reply1,
                                       "s", "com.example.foo");
                assert(r >= 0);
                r = sd_bus_message_read(reply1, "s", &owner);
                assert(r >= 0);
                assert(!strcmp(owner, unique_name2));

                r = sd_bus_call_method(bus2, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "ReleaseName", NULL, NULL,
                                       "s", "com.example.foo");
                assert(r >= 0);

                r = sd_bus_call_method(bus1, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "GetNameOwner", NULL, &reply2,
                                       "s", "com.example.foo");
                assert(r >= 0);
                r = sd_bus_message_read(reply2, "s", &owner);
                assert(r >= 0);
                assert(!strcmp(owner, unique_name1));

                r = sd_bus_call_method(bus1, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "ReleaseName", NULL, NULL,
                                       "s", "com.example.foo");
                assert(r >= 0);
        }

        /* request currently owned name and fail to replace it */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus1 = NULL, *bus2 = NULL;
                _c_cleanup_(sd_bus_message_unrefp) sd_bus_message *reply1 = NULL, *reply2 = NULL;
                const char *unique_name1, *unique_name2, *owner;

                util_broker_connect(broker, &bus1);
                util_broker_connect(broker, &bus2);

                r = sd_bus_get_unique_name(bus1, &unique_name1);
                r = sd_bus_get_unique_name(bus2, &unique_name2);

                r = sd_bus_call_method(bus1, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "RequestName", NULL, NULL,
                                       "su", "com.example.foo", 0);
                assert(r >= 0);

                r = sd_bus_call_method(bus2, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "RequestName", NULL, NULL,
                                       "su", "com.example.foo", DBUS_NAME_FLAG_REPLACE_EXISTING);
                assert(r >= 0);

                r = sd_bus_call_method(bus2, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "GetNameOwner", NULL, &reply1,
                                       "s", "com.example.foo");
                assert(r >= 0);
                r = sd_bus_message_read(reply1, "s", &owner);
                assert(r >= 0);
                assert(!strcmp(owner, unique_name1));

                r = sd_bus_call_method(bus1, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "ReleaseName", NULL, NULL,
                                       "s", "com.example.foo");
                assert(r >= 0);

                r = sd_bus_call_method(bus1, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "GetNameOwner", NULL, &reply2,
                                       "s", "com.example.foo");
                assert(r >= 0);
                r = sd_bus_message_read(reply2, "s", &owner);
                assert(r >= 0);
                assert(!strcmp(owner, unique_name2));

                r = sd_bus_call_method(bus2, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "ReleaseName", NULL, NULL,
                                       "s", "com.example.foo");
                assert(r >= 0);
        }

        /* request currently owned name, but don't try to replace it */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus1 = NULL, *bus2 = NULL;
                _c_cleanup_(sd_bus_message_unrefp) sd_bus_message *reply1 = NULL, *reply2 = NULL;
                const char *unique_name1, *unique_name2, *owner;

                util_broker_connect(broker, &bus1);
                util_broker_connect(broker, &bus2);

                r = sd_bus_get_unique_name(bus1, &unique_name1);
                r = sd_bus_get_unique_name(bus2, &unique_name2);

                r = sd_bus_call_method(bus1, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "RequestName", NULL, NULL,
                                       "su", "com.example.foo", 0);
                assert(r >= 0);

                r = sd_bus_call_method(bus2, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "RequestName", NULL, NULL,
                                       "su", "com.example.foo", 0);
                assert(r >= 0);

                r = sd_bus_call_method(bus2, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "GetNameOwner", NULL, &reply1,
                                       "s", "com.example.foo");
                assert(r >= 0);
                r = sd_bus_message_read(reply1, "s", &owner);
                assert(r >= 0);
                assert(!strcmp(owner, unique_name1));

                r = sd_bus_call_method(bus1, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "ReleaseName", NULL, NULL,
                                       "s", "com.example.foo");
                assert(r >= 0);

                r = sd_bus_call_method(bus1, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "GetNameOwner", NULL, &reply2,
                                       "s", "com.example.foo");
                assert(r >= 0);
                r = sd_bus_message_read(reply2, "s", &owner);
                assert(r >= 0);
                assert(!strcmp(owner, unique_name2));

                r = sd_bus_call_method(bus2, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "ReleaseName", NULL, NULL,
                                       "s", "com.example.foo");
                assert(r >= 0);
        }

        /* request reserved well-known name */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                util_broker_connect(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "RequestName", &error, NULL,
                                       "su", "org.freedesktop.DBus", 0);
                assert(r < 0);
                assert(!strcmp(error.name, "org.freedesktop.DBus.Error.InvalidArgs"));
        }

        /* request our own unique-name */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                const char *unique_name;

                util_broker_connect(broker, &bus);

                r = sd_bus_get_unique_name(bus, &unique_name);
                assert(r >= 0);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "RequestName", &error, NULL,
                                       "su", unique_name, 0);
                assert(r < 0);
                assert(!strcmp(error.name, "org.freedesktop.DBus.Error.InvalidArgs"));
        }

        /* request invalid name */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                util_broker_connect(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "RequestName", &error, NULL,
                                       "su", "org", 0);
                assert(r < 0);
                assert(!strcmp(error.name, "org.freedesktop.DBus.Error.InvalidArgs"));
        }

        util_broker_terminate(broker);
}

static void test_release_name(void) {
        _c_cleanup_(util_broker_freep) Broker *broker = NULL;
        int r;

        util_broker_new(&broker);
        util_broker_spawn(broker);

        /* release valid well-known name that does not exist on the bus */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                util_broker_connect(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "GetNameOwner", &error, NULL,
                                       "s", "com.example.foo");
                assert(r < 0);
                assert(!strcmp(error.name, "org.freedesktop.DBus.Error.NameHasNoOwner"));

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "ReleaseName", NULL, NULL,
                                       "s", "com.example.foo");
                assert(r >= 0);
        }

        /* request valid well-known name and release it again */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                util_broker_connect(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "RequestName", NULL, NULL,
                                       "su", "com.example.foo", 0);
                assert(r >= 0);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "ReleaseName", NULL, NULL,
                                       "s", "com.example.foo");
                assert(r >= 0);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "GetNameOwner", &error, NULL,
                                       "s", "com.example.foo");
                assert(r < 0);
                assert(!strcmp(error.name, "org.freedesktop.DBus.Error.NameHasNoOwner"));
        }

        /* request valid well-known name and try to release it from a different peer */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus1 = NULL, *bus2 = NULL;
                _c_cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
                const char *unique_name, *owner;

                util_broker_connect(broker, &bus1);
                util_broker_connect(broker, &bus2);

                r = sd_bus_get_unique_name(bus1, &unique_name);
                assert(r >= 0);

                r = sd_bus_call_method(bus1, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "RequestName", NULL, NULL,
                                       "su", "com.example.foo", 0);
                assert(r >= 0);

                r = sd_bus_call_method(bus2, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "ReleaseName", NULL, NULL,
                                       "s", "com.example.foo");
                assert(r >= 0);

                r = sd_bus_call_method(bus1, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "GetNameOwner", NULL, &reply,
                                       "s", "com.example.foo");
                assert(r >= 0);
                r = sd_bus_message_read(reply, "s", &owner);
                assert(r >= 0);
                assert(!strcmp(owner, unique_name));

                r = sd_bus_call_method(bus2, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "ReleaseName", NULL, NULL,
                                       "s", "com.example.foo");
                assert(r >= 0);
        }

        /* release reserved well-known name */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                util_broker_connect(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "ReleaseName", &error, NULL,
                                       "s", "org.freedesktop.DBus");
                assert(r < 0);
                assert(!strcmp(error.name, "org.freedesktop.DBus.Error.InvalidArgs"));
        }

        /* release our own unique-name */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                const char *unique_name;

                util_broker_connect(broker, &bus);

                r = sd_bus_get_unique_name(bus, &unique_name);
                assert(r >= 0);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "ReleaseName", &error, NULL,
                                       "s", unique_name);
                assert(r < 0);
                assert(!strcmp(error.name, "org.freedesktop.DBus.Error.InvalidArgs"));
        }

        /* release invalid name */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                util_broker_connect(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "ReleaseName", &error, NULL,
                                       "s", "org");
                assert(r < 0);
                assert(!strcmp(error.name, "org.freedesktop.DBus.Error.InvalidArgs"));
        }

        util_broker_terminate(broker);
}

int main(int argc, char **argv) {
        test_hello();
        test_request_name();
        test_release_name();
/*
        test_get_name_owner(address, addrlen);
        test_name_has_owner(address, addrlen);
        test_list_names(address, addrlen);
        test_list_activatable_names(address, addrlen);
        test_list_queued_owners(address, addrlen);
        test_get_connection_unix_user(address, addrlen);
        test_get_connection_unix_process_id(address, addrlen);
*/
        return 0;
}

#if 0

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

        /* clean up the name */
        r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "ReleaseName", NULL, NULL,
                               "s", "com.example.foo");
        assert(r >= 0);
}

static void test_driver_list_names(struct sockaddr_un *address, socklen_t addrlen) {
        _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        sd_bus_message *reply = NULL;
        const char *unique_name, *name;
        bool found_driver_name = false, found_unique_name = false, found_well_known_name = false, found_unexpected_name = false;
        int r;

        fprintf(stderr, " - ListNames()\n");

        bus = connect_bus(address, addrlen);

        r = sd_bus_get_unique_name(bus, &unique_name);
        assert(r >= 0);

        /* request a name */
        r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "RequestName", NULL, NULL,
                               "su", "com.example.foo", 0);
        assert(r >= 0);

        /* list names */
        r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "ListNames", NULL, &reply,
                               "");
        assert(r >= 0);
        r = sd_bus_message_enter_container(reply, 'a', "s");
        assert(r >= 0);

        while (!sd_bus_message_at_end(reply, false)) {
                r = sd_bus_message_read(reply, "s", &name);
                assert(r >= 0);
                if (!strcmp(name, "org.freedesktop.DBus")) {
                        assert(!found_driver_name);
                        found_driver_name = true;
                } else if (!strcmp(name, "com.example.foo")) {
                        assert(!found_well_known_name);
                        found_well_known_name = true;
                } else if (!strcmp(name, unique_name)) {
                        assert(!found_unique_name);
                        found_unique_name = true;
                } else if (name[0] != ':')
                        found_unexpected_name = true;
        }

        r = sd_bus_message_exit_container(reply);
        assert(r >= 0);
        sd_bus_message_unref(reply);

        assert(found_driver_name && found_well_known_name && found_unique_name);
        assert(!found_unexpected_name);

        /* clean up the name */
        r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "ReleaseName", NULL, NULL,
                               "s", "com.example.foo");
        assert(r >= 0);
}

static void test_driver_list_activatable_names(struct sockaddr_un *address, socklen_t addrlen) {
        _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        sd_bus_message *reply = NULL;
        const char *unique_name, *name;
        int r;

        fprintf(stderr, " - ListActivatableNames()\n");

        bus = connect_bus(address, addrlen);

        r = sd_bus_get_unique_name(bus, &unique_name);
        assert(r >= 0);

        /* request a name */
        r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "RequestName", NULL, NULL,
                               "su", "com.example.foo", 0);
        assert(r >= 0);

        /*
         * List activatable names, we don't have any real ones to test, so just verify that the driver is
         * listed and nothing else.
         */
        r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "ListActivatableNames", NULL, &reply,
                               "");
        assert(r >= 0);
        r = sd_bus_message_enter_container(reply, 'a', "s");
        assert(r >= 0);
        r = sd_bus_message_read(reply, "s", &name);
        assert(r >= 0);
        assert(!strcmp(name, "org.freedesktop.DBus"));
        r = sd_bus_message_exit_container(reply);
        assert(r >= 0);
        sd_bus_message_unref(reply);

        /* clean up the name */
        r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "ReleaseName", NULL, NULL,
                               "s", "com.example.foo");
        assert(r >= 0);
}

static void test_driver_list_queued_owners(struct sockaddr_un *address, socklen_t addrlen) {
        _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus1 = NULL, *bus2 = NULL;
        sd_bus_message *reply = NULL;
        sd_bus_error error = SD_BUS_ERROR_NULL;
        const char *unique_name1, *unique_name2, *owner;
        int r;

        fprintf(stderr, " - ListQueuedOwners()\n");

        bus1 = connect_bus(address, addrlen);
        bus2 = connect_bus(address, addrlen);

        r = sd_bus_get_unique_name(bus1, &unique_name1);
        assert(r >= 0);

        r = sd_bus_get_unique_name(bus2, &unique_name2);
        assert(r >= 0);

        /*
         * Request the same name twice, make sure that the order of the queue is different from the order
         * the names were requested in, and the order of the client's unique names.
         */
        r = sd_bus_call_method(bus1, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "RequestName", NULL, NULL,
                               "su", "com.example.foo", DBUS_NAME_FLAG_ALLOW_REPLACEMENT);
        assert(r >= 0);

        r = sd_bus_call_method(bus2, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "RequestName", NULL, NULL,
                               "su", "com.example.foo", DBUS_NAME_FLAG_REPLACE_EXISTING);
        assert(r >= 0);

        /* get the owners */
        r = sd_bus_call_method(bus1, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "ListQueuedOwners", NULL, &reply,
                               "s", "com.example.foo");
        assert(r >= 0);
        r = sd_bus_message_enter_container(reply, 'a', "s");
        assert(r >= 0);
        r = sd_bus_message_read(reply, "s", &owner);
        assert(r >= 0);
        assert(!strcmp(owner, unique_name2));
        r = sd_bus_message_read(reply, "s", &owner);
        assert(r >= 0);
        assert(!strcmp(owner, unique_name1));
        r = sd_bus_message_exit_container(reply);
        assert(r >= 0);
        sd_bus_message_unref(reply);

        /* list owners of a unique name */
        r = sd_bus_call_method(bus1, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "ListQueuedOwners", NULL, &reply,
                               "s", unique_name1);
        assert(r >= 0);
        r = sd_bus_message_enter_container(reply, 'a', "s");
        assert(r >= 0);
        r = sd_bus_message_read(reply, "s", &owner);
        assert(r >= 0);
        assert(!strcmp(owner, unique_name1));
        r = sd_bus_message_exit_container(reply);
        assert(r >= 0);
        sd_bus_message_unref(reply);

        /* list owners of the driver */
        r = sd_bus_call_method(bus1, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "ListQueuedOwners", NULL, &reply,
                               "s", "org.freedesktop.DBus");
        assert(r >= 0);
        r = sd_bus_message_enter_container(reply, 'a', "s");
        assert(r >= 0);
        r = sd_bus_message_read(reply, "s", &owner);
        assert(r >= 0);
        assert(!strcmp(owner, "org.freedesktop.DBus"));
        r = sd_bus_message_exit_container(reply);
        assert(r >= 0);
        sd_bus_message_unref(reply);

        /* list the owners of a name that does not exist */
        r = sd_bus_call_method(bus1, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "ListQueuedOwners", &error, NULL,
                               "s", "com.example.bar");
        assert(r < 0);
        assert(!strcmp(error.name, "org.freedesktop.DBus.Error.NameHasNoOwner"));
        sd_bus_error_free(&error);

        /* XXX: test invalid name */

        /* clean up the name */
        r = sd_bus_call_method(bus1, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "ReleaseName", NULL, NULL,
                               "s", "com.example.foo");
        assert(r >= 0);
}

static void test_driver_get_connection_unix_user(struct sockaddr_un *address, socklen_t addrlen) {
        _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        sd_bus_message *reply = NULL;
        const char *unique_name;
        uid_t uid;
        int r;

        fprintf(stderr, " - GetConnectionUnixUser()\n");

        bus = connect_bus(address, addrlen);

        r = sd_bus_get_unique_name(bus, &unique_name);
        assert(r >= 0);

        /* XXX: check invalid flags */

        /* request a name */
        r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "RequestName", NULL, NULL,
                               "su", "com.example.foo", 0);
        assert(r >= 0);

        /* get uid of driver */
        r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "GetConnectionUnixUser", NULL, &reply,
                               "s", "org.freedesktop.DBus", 0);
        assert(r >= 0);
        r = sd_bus_message_read(reply, "u", &uid);
        assert(r >= 0);
        assert(uid == getuid());
        sd_bus_message_unref(reply);

        /* get uid of our well-known name */
        r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "GetConnectionUnixUser", NULL, &reply,
                               "s", "com.example.foo", 0);
        assert(r >= 0);
        r = sd_bus_message_read(reply, "u", &uid);
        assert(r >= 0);
        assert(uid == getuid());
        sd_bus_message_unref(reply);

        /* get uid of our unique name */
        r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "GetConnectionUnixUser", NULL, &reply,
                               "s", unique_name);
        assert(r >= 0);
        r = sd_bus_message_read(reply, "u", &uid);
        assert(r >= 0);
        assert(uid == getuid());
        sd_bus_message_unref(reply);

        /* XXX: test invalid name */

        /* clean up the name */
        r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "ReleaseName", NULL, NULL,
                               "s", "com.example.foo");
        assert(r >= 0);
}

static void test_driver_get_connection_unix_process_id(struct sockaddr_un *address, socklen_t addrlen) {
        _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        sd_bus_message *reply = NULL;
        const char *unique_name;
        pid_t pid;
        int r;

        fprintf(stderr, " - GetConnectionUnixProcessID()\n");

        bus = connect_bus(address, addrlen);

        r = sd_bus_get_unique_name(bus, &unique_name);
        assert(r >= 0);

        /* XXX: check invalid flags */

        /* request a name */
        r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "RequestName", NULL, NULL,
                               "su", "com.example.foo", 0);
        assert(r >= 0);

        /* get pid of driver */
        r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "GetConnectionUnixProcessID", NULL, NULL,
                               "s", "org.freedesktop.DBus", 0);
        assert(r >= 0);
        /* XXX: verify that this has the right value */

        /* get pid of our well-known name */
        r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "GetConnectionUnixProcessID", NULL, &reply,
                               "s", "com.example.foo", 0);
        assert(r >= 0);
        r = sd_bus_message_read(reply, "u", &pid);
        assert(r >= 0);
        assert(pid == getpid());
        sd_bus_message_unref(reply);

        /* get uid of our unique name */
        r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "GetConnectionUnixProcessID", NULL, &reply,
                               "s", unique_name);
        assert(r >= 0);
        r = sd_bus_message_read(reply, "u", &pid);
        assert(r >= 0);
        assert(pid == getpid());
        sd_bus_message_unref(reply);

        /* XXX: test invalid name */

        /* clean up the name */
        r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "ReleaseName", NULL, NULL,
                               "s", "com.example.foo");
        assert(r >= 0);
}

static void test_driver_api(struct sockaddr_un *address, socklen_t addrlen) {
        _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int r;


        bus = connect_bus(address, addrlen);

        r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "RequestName", NULL, NULL,
                               "su", "com.example.baz", 0);
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
#endif
