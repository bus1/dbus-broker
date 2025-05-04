/*
 * Basic Broker Driver API Tests
 */

#undef NDEBUG
#include <c-stdaux.h>
#include <stdlib.h>
#include "dbus/protocol.h"
#include "util/proc.h"
#include "util/selinux.h"
#include "util-broker.h"

static void test_unknown(void) {
        _c_cleanup_(util_broker_freep) Broker *broker = NULL;
        int r;

        util_broker_new(&broker);
        util_broker_spawn(broker);

        /* call method on unknown interface */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                util_broker_connect(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.Foo",
                                       "GetId", &error, NULL,
                                       "");
                c_assert(r < 0);
                c_assert(!strcmp(error.name, "org.freedesktop.DBus.Error.UnknownInterface"));
        }

        /* call unknown method */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                util_broker_connect(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "Foo", &error, NULL,
                                       "");
                c_assert(r < 0);
                c_assert(!strcmp(error.name, "org.freedesktop.DBus.Error.UnknownMethod"));
        }

        /* call unknown method without interface */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                util_broker_connect(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", NULL,
                                       "Foo", &error, NULL,
                                       "");
                c_assert(r < 0);
                c_assert(!strcmp(error.name, "org.freedesktop.DBus.Error.UnknownMethod"));
        }

        util_broker_terminate(broker);
}

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
                c_assert(r >= 0);
                c_assert(!strcmp(unique_name, ":1.0"));

                /* calling Hello() again is not valid */
                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "Hello", &error, NULL,
                                       "");
                c_assert(r < 0);
                c_assert(!strcmp(error.name, "org.freedesktop.DBus.Error.Failed"));
        }

        /* try to call a hypothetical future Hello2() and check that falling back to Hello() works when Hello2() fails */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                const char *unique_name = NULL;

                util_broker_connect_raw(broker, &bus);

                /* do the Hello2(), verify that it fails */
                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "Foo", &error, NULL,
                                       "");
                c_assert(r < 0);
                c_assert(!strcmp(error.name, "org.freedesktop.DBus.Error.AccessDenied"));

                /* same without an interface */
                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", NULL,
                                       "Foo", &error, NULL,
                                       "");
                c_assert(r < 0);
                c_assert(!strcmp(error.name, "org.freedesktop.DBus.Error.AccessDenied"));

                /* the same again, but Hello() on an alternative interface */
                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.Foo",
                                       "Hello", &error, NULL,
                                       "");
                c_assert(r < 0);
                c_assert(!strcmp(error.name, "org.freedesktop.DBus.Error.AccessDenied"));

                /* falling back to Hello() works */
                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "Hello", NULL, &reply,
                                       "");

                r = sd_bus_message_read(reply, "s", &unique_name);
                c_assert(r >= 0);
                c_assert(!strcmp(unique_name, ":1.1"));
        }

        /* try to send a message on the bus before Hello(), see that it fails and the client is disconnected */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                util_broker_connect_raw(broker, &bus);

                /* try to make a method call on a (fictional) other client (not on the driver) */
                r = sd_bus_call_method(bus, "com.example.foobar", "/com/example/foo", "com.example.Foo",
                                       "Bar", &error, NULL,
                                       "");
                c_assert(r == -ECONNRESET);

                /* now try to call Hello() (or anything else), to verify that the client was disconnected */
                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "Hello", NULL, NULL,
                                       "");
                c_assert(r == -ENOTCONN);
        }

        util_broker_terminate(broker);
}

static void test_request_name(void) {
        _c_cleanup_(util_broker_freep) Broker *broker = NULL;
        int r;

        util_broker_new(&broker);
        util_broker_spawn(broker);

        /* XXX: test invalid flags? */

        /* request name before registering */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                util_broker_connect_raw(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "RequestName", &error, NULL,
                                       "su", "com.example.foo", 0);
                c_assert(!strcmp(error.name, "org.freedesktop.DBus.Error.AccessDenied"));
        }

        /* request valid well-known name and release it again */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
                const char *unique_name, *owner;

                util_broker_connect(broker, &bus);

                r = sd_bus_get_unique_name(bus, &unique_name);
                c_assert(r >= 0);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "RequestName", NULL, NULL,
                                       "su", "com.example.foo", 0);
                c_assert(r >= 0);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "GetNameOwner", NULL, &reply,
                                       "s", "com.example.foo");
                c_assert(r >= 0);
                r = sd_bus_message_read(reply, "s", &owner);
                c_assert(r >= 0);
                c_assert(!strcmp(owner, unique_name));

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "ReleaseName", NULL, NULL,
                                       "s", "com.example.foo");
                c_assert(r >= 0);
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
                c_assert(r >= 0);

                r = sd_bus_call_method(bus2, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "RequestName", NULL, NULL,
                                       "su", "com.example.foo", DBUS_NAME_FLAG_REPLACE_EXISTING);
                c_assert(r >= 0);

                r = sd_bus_call_method(bus2, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "GetNameOwner", NULL, &reply1,
                                       "s", "com.example.foo");
                c_assert(r >= 0);
                r = sd_bus_message_read(reply1, "s", &owner);
                c_assert(r >= 0);
                c_assert(!strcmp(owner, unique_name2));

                r = sd_bus_call_method(bus2, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "ReleaseName", NULL, NULL,
                                       "s", "com.example.foo");
                c_assert(r >= 0);

                r = sd_bus_call_method(bus1, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "GetNameOwner", NULL, &reply2,
                                       "s", "com.example.foo");
                c_assert(r >= 0);
                r = sd_bus_message_read(reply2, "s", &owner);
                c_assert(r >= 0);
                c_assert(!strcmp(owner, unique_name1));

                r = sd_bus_call_method(bus1, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "ReleaseName", NULL, NULL,
                                       "s", "com.example.foo");
                c_assert(r >= 0);
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
                c_assert(r >= 0);

                r = sd_bus_call_method(bus2, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "RequestName", NULL, NULL,
                                       "su", "com.example.foo", DBUS_NAME_FLAG_REPLACE_EXISTING);
                c_assert(r >= 0);

                r = sd_bus_call_method(bus2, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "GetNameOwner", NULL, &reply1,
                                       "s", "com.example.foo");
                c_assert(r >= 0);
                r = sd_bus_message_read(reply1, "s", &owner);
                c_assert(r >= 0);
                c_assert(!strcmp(owner, unique_name1));

                r = sd_bus_call_method(bus1, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "ReleaseName", NULL, NULL,
                                       "s", "com.example.foo");
                c_assert(r >= 0);

                r = sd_bus_call_method(bus1, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "GetNameOwner", NULL, &reply2,
                                       "s", "com.example.foo");
                c_assert(r >= 0);
                r = sd_bus_message_read(reply2, "s", &owner);
                c_assert(r >= 0);
                c_assert(!strcmp(owner, unique_name2));

                r = sd_bus_call_method(bus2, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "ReleaseName", NULL, NULL,
                                       "s", "com.example.foo");
                c_assert(r >= 0);
        }

        /* request currently owned name, but don't try to replace it */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus1 = NULL, *bus2 = NULL;
                _c_cleanup_(sd_bus_message_unrefp) sd_bus_message *reply1 = NULL, *reply2 = NULL;
                const char *unique_name1, *unique_name2, *owner;

                util_broker_connect(broker, &bus1);
                util_broker_connect(broker, &bus2);

                r = sd_bus_get_unique_name(bus1, &unique_name1);
                c_assert(r >= 0);
                r = sd_bus_get_unique_name(bus2, &unique_name2);
                c_assert(r >= 0);

                r = sd_bus_call_method(bus1, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "RequestName", NULL, NULL,
                                       "su", "com.example.foo", 0);
                c_assert(r >= 0);

                r = sd_bus_call_method(bus2, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "RequestName", NULL, NULL,
                                       "su", "com.example.foo", 0);
                c_assert(r >= 0);

                r = sd_bus_call_method(bus2, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "GetNameOwner", NULL, &reply1,
                                       "s", "com.example.foo");
                c_assert(r >= 0);
                r = sd_bus_message_read(reply1, "s", &owner);
                c_assert(r >= 0);
                c_assert(!strcmp(owner, unique_name1));

                r = sd_bus_call_method(bus1, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "ReleaseName", NULL, NULL,
                                       "s", "com.example.foo");
                c_assert(r >= 0);

                r = sd_bus_call_method(bus1, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "GetNameOwner", NULL, &reply2,
                                       "s", "com.example.foo");
                c_assert(r >= 0);
                r = sd_bus_message_read(reply2, "s", &owner);
                c_assert(r >= 0);
                c_assert(!strcmp(owner, unique_name2));

                r = sd_bus_call_method(bus2, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "ReleaseName", NULL, NULL,
                                       "s", "com.example.foo");
                c_assert(r >= 0);
        }

        /* request reserved well-known name */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                util_broker_connect(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "RequestName", &error, NULL,
                                       "su", "org.freedesktop.DBus", 0);
                c_assert(r < 0);
                c_assert(!strcmp(error.name, "org.freedesktop.DBus.Error.InvalidArgs"));
        }

        /* request our own unique-name */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                const char *unique_name;

                util_broker_connect(broker, &bus);

                r = sd_bus_get_unique_name(bus, &unique_name);
                c_assert(r >= 0);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "RequestName", &error, NULL,
                                       "su", unique_name, 0);
                c_assert(r < 0);
                c_assert(!strcmp(error.name, "org.freedesktop.DBus.Error.InvalidArgs"));
        }

        /* request invalid name */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                util_broker_connect(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "RequestName", &error, NULL,
                                       "su", "org", 0);
                c_assert(r < 0);
                c_assert(!strcmp(error.name, "org.freedesktop.DBus.Error.InvalidArgs"));
        }

        util_broker_terminate(broker);
}

static void test_release_name(void) {
        _c_cleanup_(util_broker_freep) Broker *broker = NULL;
        int r;

        util_broker_new(&broker);
        util_broker_spawn(broker);

        /* release name before registering */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                util_broker_connect_raw(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "ReleaseName", &error, NULL,
                                       "s", "com.example.foo");
                c_assert(!strcmp(error.name, "org.freedesktop.DBus.Error.AccessDenied"));
        }

        /* release valid well-known name that does not exist on the bus */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                util_broker_connect(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "GetNameOwner", &error, NULL,
                                       "s", "com.example.foo");
                c_assert(r < 0);
                c_assert(!strcmp(error.name, "org.freedesktop.DBus.Error.NameHasNoOwner"));

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "ReleaseName", NULL, NULL,
                                       "s", "com.example.foo");
                c_assert(r >= 0);
        }

        /* request valid well-known name and release it again */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                util_broker_connect(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "RequestName", NULL, NULL,
                                       "su", "com.example.foo", 0);
                c_assert(r >= 0);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "ReleaseName", NULL, NULL,
                                       "s", "com.example.foo");
                c_assert(r >= 0);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "GetNameOwner", &error, NULL,
                                       "s", "com.example.foo");
                c_assert(r < 0);
                c_assert(!strcmp(error.name, "org.freedesktop.DBus.Error.NameHasNoOwner"));
        }

        /* request valid well-known name and try to release it from a different peer */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus1 = NULL, *bus2 = NULL;
                _c_cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
                const char *unique_name, *owner;

                util_broker_connect(broker, &bus1);
                util_broker_connect(broker, &bus2);

                r = sd_bus_get_unique_name(bus1, &unique_name);
                c_assert(r >= 0);

                r = sd_bus_call_method(bus1, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "RequestName", NULL, NULL,
                                       "su", "com.example.foo", 0);
                c_assert(r >= 0);

                r = sd_bus_call_method(bus2, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "ReleaseName", NULL, NULL,
                                       "s", "com.example.foo");
                c_assert(r >= 0);

                r = sd_bus_call_method(bus1, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "GetNameOwner", NULL, &reply,
                                       "s", "com.example.foo");
                c_assert(r >= 0);
                r = sd_bus_message_read(reply, "s", &owner);
                c_assert(r >= 0);
                c_assert(!strcmp(owner, unique_name));

                r = sd_bus_call_method(bus2, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "ReleaseName", NULL, NULL,
                                       "s", "com.example.foo");
                c_assert(r >= 0);
        }

        /* release reserved well-known name */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                util_broker_connect(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "ReleaseName", &error, NULL,
                                       "s", "org.freedesktop.DBus");
                c_assert(r < 0);
                c_assert(!strcmp(error.name, "org.freedesktop.DBus.Error.InvalidArgs"));
        }

        /* release our own unique-name */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                const char *unique_name;

                util_broker_connect(broker, &bus);

                r = sd_bus_get_unique_name(bus, &unique_name);
                c_assert(r >= 0);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "ReleaseName", &error, NULL,
                                       "s", unique_name);
                c_assert(r < 0);
                c_assert(!strcmp(error.name, "org.freedesktop.DBus.Error.InvalidArgs"));
        }

        /* release invalid name */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                util_broker_connect(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "ReleaseName", &error, NULL,
                                       "s", "org");
                c_assert(r < 0);
                c_assert(!strcmp(error.name, "org.freedesktop.DBus.Error.InvalidArgs"));
        }

        util_broker_terminate(broker);
}

static void test_get_name_owner(void) {
        _c_cleanup_(util_broker_freep) Broker *broker = NULL;
        int r;

        util_broker_new(&broker);
        util_broker_spawn(broker);

        /* get name-owner before registering */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                util_broker_connect_raw(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "GetNameOwner", &error, NULL,
                                       "s", "com.example.foo");
                c_assert(!strcmp(error.name, "org.freedesktop.DBus.Error.AccessDenied"));
        }

        /* get non-existent name */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                util_broker_connect(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "GetNameOwner", &error, NULL,
                                       "s", "com.example.foo");
                c_assert(r < 0);
                c_assert(!strcmp(error.name, "org.freedesktop.DBus.Error.NameHasNoOwner"));
        }

        /* get by unique name */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
                const char *unique_name, *owner;

                util_broker_connect(broker, &bus);

                r = sd_bus_get_unique_name(bus, &unique_name);
                c_assert(r >= 0);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "GetNameOwner", NULL, &reply,
                                       "s", unique_name);
                c_assert(r >= 0);
                r = sd_bus_message_read(reply, "s", &owner);
                c_assert(!strcmp(owner, unique_name));
        }

        /* get by well-known name */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
                const char *unique_name, *owner;

                util_broker_connect(broker, &bus);

                r = sd_bus_get_unique_name(bus, &unique_name);
                c_assert(r >= 0);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "RequestName", NULL, NULL,
                                       "su", "com.example.foo", 0);
                c_assert(r >= 0);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "GetNameOwner", NULL, &reply,
                                       "s", "com.example.foo");
                c_assert(r >= 0);
                r = sd_bus_message_read(reply, "s", &owner);
                c_assert(!strcmp(owner, unique_name));

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "ReleaseName", NULL, NULL,
                                       "s", "com.example.foo");
                c_assert(r >= 0);
        }

        /* get driver name */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
                const char *owner;

                util_broker_connect(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "GetNameOwner", NULL, &reply,
                                       "s", "org.freedesktop.DBus");
                c_assert(r >= 0);
                r = sd_bus_message_read(reply, "s", &owner);
                c_assert(!strcmp(owner, "org.freedesktop.DBus"));
        }

        /* get invalid name */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                util_broker_connect(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "GetNameOwner", &error, NULL,
                                       "s", "org");
                c_assert(r < 0);
                c_assert(!strcmp(error.name, "org.freedesktop.DBus.Error.NameHasNoOwner"));
        }

        util_broker_terminate(broker);
}

static void test_name_has_owner(void) {
        _c_cleanup_(util_broker_freep) Broker *broker = NULL;
        int r;

        util_broker_new(&broker);
        util_broker_spawn(broker);

        /* check if name has owner before registering */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                util_broker_connect_raw(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "NameHasOwner", &error, NULL,
                                       "s", "com.example.foo");
                c_assert(!strcmp(error.name, "org.freedesktop.DBus.Error.AccessDenied"));
        }

        /* check non-existent name */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
                int owned;

                util_broker_connect(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "NameHasOwner", NULL, &reply,
                                       "s", "com.example.foo");
                c_assert(r >= 0);
                r = sd_bus_message_read(reply, "b", &owned);
                c_assert(r >= 0);
                c_assert(!owned);
        }

        /* check unique name */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
                const char *unique_name;
                int owned;

                util_broker_connect(broker, &bus);

                r = sd_bus_get_unique_name(bus, &unique_name);
                c_assert(r >= 0);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "NameHasOwner", NULL, &reply,
                                       "s", unique_name);
                c_assert(r >= 0);
                r = sd_bus_message_read(reply, "b", &owned);
                c_assert(r >= 0);
                c_assert(owned);
        }

        /* check well-known name */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
                int owned;

                util_broker_connect(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "RequestName", NULL, NULL,
                                       "su", "com.example.foo", 0);
                c_assert(r >= 0);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "NameHasOwner", NULL, &reply,
                                       "s", "com.example.foo");
                c_assert(r >= 0);
                r = sd_bus_message_read(reply, "b", &owned);
                c_assert(r >= 0);
                c_assert(owned);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "ReleaseName", NULL, NULL,
                                       "s", "com.example.foo");
                c_assert(r >= 0);
        }

        /* check driver name */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
                int owned;

                util_broker_connect(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "NameHasOwner", NULL, &reply,
                                       "s", "org.freedesktop.DBus");
                c_assert(r >= 0);
                r = sd_bus_message_read(reply, "b", &owned);
                c_assert(r >= 0);
                c_assert(owned);
        }

        /* check invalid name */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
                int owned;

                util_broker_connect(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "NameHasOwner", NULL, &reply,
                                       "s", "org");
                c_assert(r >= 0);
                r = sd_bus_message_read(reply, "b", &owned);
                c_assert(r >= 0);
                c_assert(!owned);
        }

        util_broker_terminate(broker);
}

static void test_start_service_by_name(void) {
        _c_cleanup_(util_broker_freep) Broker *broker = NULL;
        int r;

        util_broker_new(&broker);
        util_broker_spawn(broker);

        /* XXX: test invalid flags? */

        /* start service by name before registering */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                util_broker_connect_raw(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "StartServiceByName", &error, NULL,
                                       "su", "com.example.foo", 0);
                c_assert(!strcmp(error.name, "org.freedesktop.DBus.Error.AccessDenied"));
        }

        /* start non-existent name */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                util_broker_connect(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "StartServiceByName", &error, NULL,
                                       "su", "com.example.foo", 0);
                c_assert(r < 0);
                c_assert(!strcmp(error.name, "org.freedesktop.DBus.Error.ServiceUnknown"));
        }

        /* start own unique name */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                const char *unique_name;

                util_broker_connect(broker, &bus);

                r = sd_bus_get_unique_name(bus, &unique_name);
                c_assert(r >= 0);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "StartServiceByName", &error, NULL,
                                       "su", unique_name, 0);
                c_assert(r < 0);
                c_assert(!strcmp(error.name, "org.freedesktop.DBus.Error.ServiceUnknown"));
        }

        /* XXX: start actual name, config must be pushed into the driver/broker first */

        /* start driver name */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                util_broker_connect(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "StartServiceByName", &error, NULL,
                                       "su", "org.freedesktop.DBus", 0);
                c_assert(r < 0);
                c_assert(!strcmp(error.name, "org.freedesktop.DBus.Error.ServiceUnknown"));
        }

        /* start pid1 name */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                util_broker_connect(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "StartServiceByName", &error, NULL,
                                       "su", "org.freedesktop.systemd1", 0);
                c_assert(r < 0);
                c_assert(!strcmp(error.name, "org.freedesktop.DBus.Error.ServiceUnknown"));
        }

        /* start invalid name */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                util_broker_connect(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "StartServiceByName", &error, NULL,
                                       "su", "org", 0);
                c_assert(r < 0);
                c_assert(!strcmp(error.name, "org.freedesktop.DBus.Error.ServiceUnknown"));
        }

        util_broker_terminate(broker);
}

static void test_update_activation_environment(void) {
        _c_cleanup_(util_broker_freep) Broker *broker = NULL;
        int r;

        util_broker_new(&broker);
        util_broker_spawn(broker);

        /* update activation environment before registering */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                util_broker_connect_raw(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "UpdateActivationEnvironment", &error, NULL,
                                       "a{ss}", 0);
                c_assert(!strcmp(error.name, "org.freedesktop.DBus.Error.AccessDenied"));
        }

        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;

                util_broker_connect(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "UpdateActivationEnvironment", NULL, NULL,
                                       "a{ss}", 1, "foo", "bar");
                c_assert(r >= 0);
        }

        util_broker_terminate(broker);
}

static void test_list_names(void) {
        _c_cleanup_(util_broker_freep) Broker *broker = NULL;
        int r;

        util_broker_new(&broker);
        util_broker_spawn(broker);

        /* list names before registering */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                util_broker_connect_raw(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "ListNames", &error, NULL,
                                       "");
                c_assert(!strcmp(error.name, "org.freedesktop.DBus.Error.AccessDenied"));
        }

        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
                const char *unique_name, *name;
                bool found_driver_name = false, found_unique_name = false, found_well_known_name = false, found_unexpected_name = false;

                util_broker_connect(broker, &bus);

                r = sd_bus_get_unique_name(bus, &unique_name);
                c_assert(r >= 0);

                /* request a name */
                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "RequestName", NULL, NULL,
                                       "su", "com.example.foo", 0);
                c_assert(r >= 0);

                /* list names */
                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "ListNames", NULL, &reply,
                                       "");
                c_assert(r >= 0);
                r = sd_bus_message_enter_container(reply, 'a', "s");
                c_assert(r >= 0);

                while (!sd_bus_message_at_end(reply, false)) {
                        r = sd_bus_message_read(reply, "s", &name);
                        c_assert(r >= 0);
                        if (!strcmp(name, "org.freedesktop.DBus")) {
                                c_assert(!found_driver_name);
                                found_driver_name = true;
                        } else if (!strcmp(name, "com.example.foo")) {
                                c_assert(!found_well_known_name);
                                found_well_known_name = true;
                        } else if (!strcmp(name, unique_name)) {
                                c_assert(!found_unique_name);
                                found_unique_name = true;
                        } else if (name[0] != ':')
                                found_unexpected_name = true;
                }

                r = sd_bus_message_exit_container(reply);
                c_assert(r >= 0);

                c_assert(found_driver_name && found_well_known_name && found_unique_name);
                c_assert(!found_unexpected_name);

                /* clean up the name */
                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "ReleaseName", NULL, NULL,
                                       "s", "com.example.foo");
                c_assert(r >= 0);
        }

        util_broker_terminate(broker);
}

static void test_list_activatable_names(void) {
        _c_cleanup_(util_broker_freep) Broker *broker = NULL;
        int r;

        util_broker_new(&broker);
        util_broker_spawn(broker);

        /* list activatable names before registering */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                util_broker_connect_raw(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "ListActivatableNames", &error, NULL,
                                       "");
                c_assert(!strcmp(error.name, "org.freedesktop.DBus.Error.AccessDenied"));
        }

        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
                const char *name;

                util_broker_connect(broker, &bus);

                /* request a name */
                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "RequestName", NULL, NULL,
                                       "su", "com.example.foo", 0);
                c_assert(r >= 0);

                /*
                 * List activatable names, we don't have any real ones to test, so just verify that the driver is
                 * listed and nothing else.
                 */
                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "ListActivatableNames", NULL, &reply,
                                       "");
                c_assert(r >= 0);
                r = sd_bus_message_enter_container(reply, 'a', "s");
                c_assert(r >= 0);
                r = sd_bus_message_read(reply, "s", &name);
                c_assert(r >= 0);
                c_assert(!strcmp(name, "org.freedesktop.DBus"));
                r = sd_bus_message_exit_container(reply);
                c_assert(r >= 0);

                /* clean up the name */
                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "ReleaseName", NULL, NULL,
                                       "s", "com.example.foo");
                c_assert(r >= 0);
        }

        util_broker_terminate(broker);
}

static void test_add_match(void) {
        _c_cleanup_(util_broker_freep) Broker *broker = NULL;
        int r;

        util_broker_new(&broker);
        util_broker_spawn(broker);

        /* add match before registering */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                util_broker_connect_raw(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "AddMatch", &error, NULL,
                                       "s", "");
                c_assert(!strcmp(error.name, "org.freedesktop.DBus.Error.AccessDenied"));
        }

        /* add invalid match */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                util_broker_connect(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "AddMatch", &error, NULL,
                                       "s", "foo");
                c_assert(r < 0);
                c_assert(!strcmp(error.name, "org.freedesktop.DBus.Error.MatchRuleInvalid"));
        }

        /* add match */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;

                util_broker_connect(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "AddMatch", NULL, NULL,
                                       "s", "sender=org.freedesktop.DBus");
                c_assert(r >= 0);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "RemoveMatch", NULL, NULL,
                                       "s", "sender=org.freedesktop.DBus");
                c_assert(r >= 0);
        }

        util_broker_terminate(broker);
}

static void test_remove_match(void) {
        _c_cleanup_(util_broker_freep) Broker *broker = NULL;
        int r;

        util_broker_new(&broker);
        util_broker_spawn(broker);

        /* remove match before registering */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                util_broker_connect_raw(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "RemoveMatch", &error, NULL,
                                       "s", "");
                c_assert(!strcmp(error.name, "org.freedesktop.DBus.Error.AccessDenied"));
        }

        /* remove invalid match */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                util_broker_connect(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "RemoveMatch", &error, NULL,
                                       "s", "foo");
                c_assert(r < 0);
                c_assert(!strcmp(error.name, "org.freedesktop.DBus.Error.MatchRuleInvalid"));
        }

        /* remove non-existent match */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                util_broker_connect(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "RemoveMatch", &error, NULL,
                                       "s", "sender=org.freedesktop.DBus");
                if (!getenv("DBUS_BROKER_TEST_DAEMON")) {
                        /* XXX: dbus-daemon is buggy, ignore for now. See <https://bugs.freedesktop.org/show_bug.cgi?id=101161> */
                        c_assert(r < 0);
                        c_assert(!strcmp(error.name, "org.freedesktop.DBus.Error.MatchRuleNotFound"));
                }
        }

        /* remove match, and verify */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                util_broker_connect(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "AddMatch", NULL, NULL,
                                       "s", "sender=org.freedesktop.DBus");
                c_assert(r >= 0);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "RemoveMatch", NULL, NULL,
                                       "s", "sender=org.freedesktop.DBus");
                c_assert(r >= 0);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "RemoveMatch", &error, NULL,
                                       "s", "sender=org.freedesktop.DBus");
                if (!getenv("DBUS_BROKER_TEST_DAEMON")) {
                        /* XXX: ignore bug in dbus-daemon, as above */
                        c_assert(r < 0);
                        c_assert(!strcmp(error.name, "org.freedesktop.DBus.Error.MatchRuleNotFound"));
                }
        }

        /* verify refcounting, add a match twice, and make sure it can be removed twice */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;

                util_broker_connect(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "AddMatch", NULL, NULL,
                                       "s", "sender=org.freedesktop.DBus");
                c_assert(r >= 0);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "AddMatch", NULL, NULL,
                                       "s", "sender=org.freedesktop.DBus");
                c_assert(r >= 0);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "RemoveMatch", NULL, NULL,
                                       "s", "sender=org.freedesktop.DBus");
                c_assert(r >= 0);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "RemoveMatch", NULL, NULL,
                                       "s", "sender=org.freedesktop.DBus");
                c_assert(r >= 0);
        }

        /* verify equality */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;

                util_broker_connect(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "AddMatch", NULL, NULL,
                                       "s", "sender=org.freedesktop.DBus,interface=org.freedesktop.DBus");
                c_assert(r >= 0);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "RemoveMatch", NULL, NULL,
                                       "s", "interface=org.freedesktop.DBus,sender=org.freedesktop.DBus");
                c_assert(r >= 0);
        }

        util_broker_terminate(broker);
}

static void test_list_queued_owners(void) {
        _c_cleanup_(util_broker_freep) Broker *broker = NULL;
        int r;

        util_broker_new(&broker);
        util_broker_spawn(broker);

        /* list name owners before registering */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                util_broker_connect_raw(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "ListQueuedOwners", &error, NULL,
                                       "s", "com.example.foo");
                c_assert(!strcmp(error.name, "org.freedesktop.DBus.Error.AccessDenied"));
        }

        /* list queued owners of a well-known name */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus1 = NULL, *bus2 = NULL;
                _c_cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
                const char *unique_name1, *unique_name2, *owner;

                util_broker_connect(broker, &bus1);
                util_broker_connect(broker, &bus2);

                r = sd_bus_get_unique_name(bus1, &unique_name1);
                c_assert(r >= 0);

                r = sd_bus_get_unique_name(bus2, &unique_name2);
                c_assert(r >= 0);

                /*
                 * Request the same name twice, make sure that the order of the queue is different from the order
                 * the names were requested in, and the order of the client's unique names.
                 */
                r = sd_bus_call_method(bus1, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "RequestName", NULL, NULL,
                                       "su", "com.example.foo", DBUS_NAME_FLAG_ALLOW_REPLACEMENT);
                c_assert(r >= 0);

                r = sd_bus_call_method(bus2, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "RequestName", NULL, NULL,
                                       "su", "com.example.foo", DBUS_NAME_FLAG_REPLACE_EXISTING);
                c_assert(r >= 0);

                /* get the owners */
                r = sd_bus_call_method(bus1, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "ListQueuedOwners", NULL, &reply,
                                       "s", "com.example.foo");
                c_assert(r >= 0);
                r = sd_bus_message_enter_container(reply, 'a', "s");
                c_assert(r >= 0);
                r = sd_bus_message_read(reply, "s", &owner);
                c_assert(r >= 0);
                c_assert(!strcmp(owner, unique_name2));
                r = sd_bus_message_read(reply, "s", &owner);
                c_assert(r >= 0);
                c_assert(!strcmp(owner, unique_name1));
                r = sd_bus_message_exit_container(reply);
                c_assert(r >= 0);

                r = sd_bus_call_method(bus2, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "ReleaseName", NULL, NULL,
                                       "s", "com.example.foo");
                c_assert(r >= 0);

                r = sd_bus_call_method(bus1, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "ReleaseName", NULL, NULL,
                                       "s", "com.example.foo");
                c_assert(r >= 0);
        }

        /* list queued owners of a unique name */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
                const char *unique_name, *owner;

                util_broker_connect(broker, &bus);

                r = sd_bus_get_unique_name(bus, &unique_name);
                c_assert(r >= 0);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "ListQueuedOwners", NULL, &reply,
                                       "s", unique_name);
                c_assert(r >= 0);
                r = sd_bus_message_enter_container(reply, 'a', "s");
                c_assert(r >= 0);
                r = sd_bus_message_read(reply, "s", &owner);
                c_assert(r >= 0);
                c_assert(!strcmp(owner, unique_name));
                r = sd_bus_message_exit_container(reply);
                c_assert(r >= 0);
        }

        /* list queued owners of the driver */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
                const char *owner;

                util_broker_connect(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "ListQueuedOwners", NULL, &reply,
                                       "s", "org.freedesktop.DBus");
                c_assert(r >= 0);
                r = sd_bus_message_enter_container(reply, 'a', "s");
                c_assert(r >= 0);
                r = sd_bus_message_read(reply, "s", &owner);
                c_assert(r >= 0);
                c_assert(!strcmp(owner, "org.freedesktop.DBus"));
                r = sd_bus_message_exit_container(reply);
                c_assert(r >= 0);
        }

        /* list queued owners of a name that does not exist */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                util_broker_connect(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "ListQueuedOwners", &error, NULL,
                                       "s", "com.example.foo");
                c_assert(r < 0);
                c_assert(!strcmp(error.name, "org.freedesktop.DBus.Error.NameHasNoOwner"));
        }

        /* list queued owners of invalid name */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                util_broker_connect(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "ListQueuedOwners", &error, NULL,
                                       "s", "org");
                c_assert(r < 0);
                c_assert(!strcmp(error.name, "org.freedesktop.DBus.Error.NameHasNoOwner"));
        }

        util_broker_terminate(broker);
}

static void test_get_connection_unix_user(void) {
        _c_cleanup_(util_broker_freep) Broker *broker = NULL;
        int r;

        util_broker_new(&broker);
        util_broker_spawn(broker);

        /* get uid before registering */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                util_broker_connect_raw(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "GetConnectionUnixUser", &error, NULL,
                                       "s", "com.example.foo");
                c_assert(!strcmp(error.name, "org.freedesktop.DBus.Error.AccessDenied"));
        }

        /* get uid of well-known name */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
                uid_t uid;

                util_broker_connect(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "RequestName", NULL, NULL,
                                       "su", "com.example.foo", 0);
                c_assert(r >= 0);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "GetConnectionUnixUser", NULL, &reply,
                                       "s", "com.example.foo");
                c_assert(r >= 0);
                r = sd_bus_message_read(reply, "u", &uid);
                c_assert(r >= 0);
                c_assert(uid == getuid());

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "ReleaseName", NULL, NULL,
                                       "s", "com.example.foo");
                c_assert(r >= 0);
        }

        /* get uid of driver */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
                uid_t uid;

                util_broker_connect(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "GetConnectionUnixUser", NULL, &reply,
                                       "s", "org.freedesktop.DBus");
                c_assert(r >= 0);
                r = sd_bus_message_read(reply, "u", &uid);
                c_assert(r >= 0);
                c_assert(uid == getuid());
        }

        /* get uid of unique name */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
                const char *unique_name;
                uid_t uid;

                util_broker_connect(broker, &bus);

                r = sd_bus_get_unique_name(bus, &unique_name);
                c_assert(r >= 0);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "GetConnectionUnixUser", NULL, &reply,
                                       "s", unique_name);
                c_assert(r >= 0);
                r = sd_bus_message_read(reply, "u", &uid);
                c_assert(r >= 0);
                c_assert(uid == getuid());
        }

        /* get uid of name that does not exist */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                util_broker_connect(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "GetConnectionUnixUser", &error, NULL,
                                       "s", "com.example.foo");
                c_assert(r < 0);
                c_assert(!strcmp(error.name, "org.freedesktop.DBus.Error.NameHasNoOwner"));
        }

        /* get uid of invalid name */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                util_broker_connect(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "GetConnectionUnixUser", &error, NULL,
                                       "s", "org");
                c_assert(r < 0);
                c_assert(!strcmp(error.name, "org.freedesktop.DBus.Error.NameHasNoOwner"));
        }

        util_broker_terminate(broker);
}

static void test_get_connection_unix_process_id(void) {
        _c_cleanup_(util_broker_freep) Broker *broker = NULL;
        int r;

        util_broker_new(&broker);
        util_broker_spawn(broker);

        /* get pid before registering */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                util_broker_connect_raw(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "GetConnectionUnixProcessID", &error, NULL,
                                       "s", "com.example.foo");
                c_assert(!strcmp(error.name, "org.freedesktop.DBus.Error.AccessDenied"));
        }

        /* get pid of well-known name */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
                pid_t pid;

                util_broker_connect(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "RequestName", NULL, NULL,
                                       "su", "com.example.foo", 0);
                c_assert(r >= 0);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "GetConnectionUnixProcessID", NULL, &reply,
                                       "s", "com.example.foo");
                c_assert(r >= 0);
                r = sd_bus_message_read(reply, "u", &pid);
                c_assert(r >= 0);
                c_assert(pid == getpid());

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "ReleaseName", NULL, NULL,
                                       "s", "com.example.foo");
                c_assert(r >= 0);
        }

        /* get pid of driver */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
                pid_t pid;

                util_broker_connect(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "GetConnectionUnixProcessID", NULL, &reply,
                                       "s", "org.freedesktop.DBus");
                c_assert(r >= 0);
                r = sd_bus_message_read(reply, "u", &pid);
                c_assert(r >= 0);
                c_assert(pid == broker->pid);
        }

        /* get pid of unique name */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
                const char *unique_name;
                pid_t pid;

                util_broker_connect(broker, &bus);

                r = sd_bus_get_unique_name(bus, &unique_name);
                c_assert(r >= 0);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "GetConnectionUnixProcessID", NULL, &reply,
                                       "s", unique_name);
                c_assert(r >= 0);
                r = sd_bus_message_read(reply, "u", &pid);
                c_assert(r >= 0);
                c_assert(pid == getpid());
        }

        /* get pid of name that does not exist */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                util_broker_connect(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "GetConnectionUnixProcessID", &error, NULL,
                                       "s", "com.example.foo");
                c_assert(r < 0);
                c_assert(!strcmp(error.name, "org.freedesktop.DBus.Error.NameHasNoOwner"));
        }

        /* get pid of invalid name */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                util_broker_connect(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "GetConnectionUnixProcessID", &error, NULL,
                                       "s", "org");
                c_assert(r < 0);
                c_assert(!strcmp(error.name, "org.freedesktop.DBus.Error.NameHasNoOwner"));
        }

        util_broker_terminate(broker);
}

static void test_verify_selinux_context(sd_bus_message *reply) {
        _c_cleanup_(c_freep) char *own_context = NULL;
        size_t n_own_context;
        int r;

        r = proc_get_seclabel(PROC_PID_SELF, &own_context, &n_own_context);
        c_assert(r >= 0);

        r = sd_bus_message_enter_container(reply, 'a', "y");
        c_assert(r >= 0);

        for (unsigned int i = 0; i < n_own_context; ++i) {
                char c;

                r = sd_bus_message_read(reply, "y", &c);
                c_assert(r >= 0);

                c_assert(own_context[i] == c);
        }

        r = sd_bus_message_exit_container(reply);
        c_assert(r >= 0);
}

static void test_verify_credentials(sd_bus_message *message) {
        bool got_uid = false, got_pid = false, got_gids = false;
        int r;

        /* We do not fail on unexpected credentials. */

        r = sd_bus_message_enter_container(message, 'a', "{sv}");
        c_assert(r >= 0);

        while ((r = sd_bus_message_enter_container(message, 'e', "sv")) > 0) {
                const char *key;

                r = sd_bus_message_read(message, "s", &key);
                c_assert(r >= 0);

                r = sd_bus_message_skip(message, "v");
                c_assert(r >= 0);

                r = sd_bus_message_exit_container(message);
                c_assert(r >= 0);

                if (strcmp(key, "UnixUserID") == 0)
                        got_uid = true;
                else if (strcmp(key, "ProcessID") == 0)
                        got_pid = true;
                else if (strcmp(key, "UnixGroupIDs") == 0)
                        got_gids = true;
        }

        r = sd_bus_message_exit_container(message);
        c_assert(r >= 0);

        c_assert(got_uid);
        c_assert(got_pid);

        if (!util_is_reference()) {
                // Group-IDs are a relatively new feature, which might not be
                // reported by the reference implementation used for this run.
                c_assert(got_gids);
        }

        /*
         * XXX: verify that we get the security label at least when SELinux is enabled
         * however, be aware that the dbus daemon does not return the label for the driver.
         */
}

static void test_get_connection_credentials(void) {
        _c_cleanup_(util_broker_freep) Broker *broker = NULL;
        int r;

        util_broker_new(&broker);
        util_broker_spawn(broker);

        /* get creds before registering */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                util_broker_connect_raw(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "GetConnectionCredentials", &error, NULL,
                                       "s", "com.example.foo");
                c_assert(!strcmp(error.name, "org.freedesktop.DBus.Error.AccessDenied"));
        }

        /* get connection credentials of well-known name */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;

                util_broker_connect(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "RequestName", NULL, NULL,
                                       "su", "com.example.foo", 0);
                c_assert(r >= 0);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "GetConnectionCredentials", NULL, &reply,
                                       "s", "com.example.foo");
                c_assert(r >= 0);

                test_verify_credentials(reply);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "ReleaseName", NULL, NULL,
                                       "s", "com.example.foo");
                c_assert(r >= 0);
        }

        /* get connection credentials of driver */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;

                util_broker_connect(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "GetConnectionCredentials", NULL, &reply,
                                       "s", "org.freedesktop.DBus");
                c_assert(r >= 0);

                test_verify_credentials(reply);
        }

        /* get connection credentials of unique name */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
                const char *unique_name;

                util_broker_connect(broker, &bus);

                r = sd_bus_get_unique_name(bus, &unique_name);
                c_assert(r >= 0);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "GetConnectionCredentials", NULL, &reply,
                                       "s", unique_name);
                c_assert(r >= 0);

                test_verify_credentials(reply);

        }

        /* get connection credentials of name that does not exist */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                util_broker_connect(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "GetConnectionCredentials", &error, NULL,
                                       "s", "com.example.foo");
                c_assert(r < 0);
                c_assert(!strcmp(error.name, "org.freedesktop.DBus.Error.NameHasNoOwner"));
        }

        /* get connection credentials of invalid name */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                util_broker_connect(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "GetConnectionCredentials", &error, NULL,
                                       "s", "org");
                c_assert(r < 0);
                c_assert(!strcmp(error.name, "org.freedesktop.DBus.Error.NameHasNoOwner"));
        }

        util_broker_terminate(broker);
}


static void test_get_connection_selinux_security_context(void) {
        _c_cleanup_(util_broker_freep) Broker *broker = NULL;
        int r;

        util_broker_new(&broker);
        util_broker_spawn(broker);

        /* get selinux context before registering */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                util_broker_connect_raw(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "GetConnectionSELinuxSecurityContext", &error, NULL,
                                       "s", "com.example.foo");
                c_assert(!strcmp(error.name, "org.freedesktop.DBus.Error.AccessDenied"));
        }

        /* get selinux context of well-known name */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                _c_cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;

                util_broker_connect(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "RequestName", NULL, NULL,
                                       "su", "com.example.foo", 0);
                c_assert(r >= 0);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "GetConnectionSELinuxSecurityContext", &error, &reply,
                                       "s", "com.example.foo");
                if (bus_selinux_is_enabled()) {
                        test_verify_selinux_context(reply);
                } else {
                        c_assert(r < 0);
                        c_assert(!strcmp(error.name, "org.freedesktop.DBus.Error.SELinuxSecurityContextUnknown"));
                }

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "ReleaseName", NULL, NULL,
                                       "s", "com.example.foo");
                c_assert(r >= 0);
        }

        /* get selinux security context of driver */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                _c_cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;

                util_broker_connect(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "GetConnectionSELinuxSecurityContext", &error, &reply,
                                       "s", "org.freedesktop.DBus");
                if (bus_selinux_is_enabled()) {
                        /* XXX: figure out how to get the expected context */
                        //test_verify_selinux_context(reply);
                } else {
                        c_assert(r < 0);
                        c_assert(!strcmp(error.name, "org.freedesktop.DBus.Error.SELinuxSecurityContextUnknown"));
                }
        }

        /* get selinux security context of unique name */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                _c_cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
                const char *unique_name;

                util_broker_connect(broker, &bus);

                r = sd_bus_get_unique_name(bus, &unique_name);
                c_assert(r >= 0);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "GetConnectionSELinuxSecurityContext", &error, &reply,
                                       "s", unique_name);
                if (bus_selinux_is_enabled()) {
                        test_verify_selinux_context(reply);
                } else {
                        c_assert(r < 0);
                        c_assert(!strcmp(error.name, "org.freedesktop.DBus.Error.SELinuxSecurityContextUnknown"));
        }

        }

        /* get selinux security context of name that does not exist */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                util_broker_connect(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "GetConnectionSELinuxSecurityContext", &error, NULL,
                                       "s", "com.example.foo");
                c_assert(r < 0);
                c_assert(!strcmp(error.name, "org.freedesktop.DBus.Error.NameHasNoOwner"));
        }

        /* get selinux security context of invalid name */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                util_broker_connect(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "GetConnectionSELinuxSecurityContext", &error, NULL,
                                       "s", "org");
                c_assert(r < 0);
                c_assert(!strcmp(error.name, "org.freedesktop.DBus.Error.NameHasNoOwner"));
        }

        util_broker_terminate(broker);
}

static void test_get_adt_audit_session_data(void) {
        _c_cleanup_(util_broker_freep) Broker *broker = NULL;
        int r;

        util_broker_new(&broker);
        util_broker_spawn(broker);

        /* get ADT before registering */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                util_broker_connect_raw(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "GetAdtAuditSessionData", &error, NULL,
                                       "s", "com.example.foo");
                c_assert(!strcmp(error.name, "org.freedesktop.DBus.Error.AccessDenied"));
        }

        /* get adt audit session data of well-known name */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                util_broker_connect(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "RequestName", NULL, NULL,
                                       "su", "com.example.foo", 0);
                c_assert(r >= 0);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "GetAdtAuditSessionData", &error, NULL,
                                       "s", "com.example.foo");
                c_assert(r < 0);
                c_assert(!strcmp(error.name, "org.freedesktop.DBus.Error.AdtAuditDataUnknown"));

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "ReleaseName", NULL, NULL,
                                       "s", "com.example.foo");
                c_assert(r >= 0);
        }

        /* get adt audit session data of driver */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                util_broker_connect(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "GetAdtAuditSessionData", &error, NULL,
                                       "s", "org.freedesktop.DBus");
                c_assert(r < 0);
                c_assert(!strcmp(error.name, "org.freedesktop.DBus.Error.AdtAuditDataUnknown"));
        }

        /* get adt audit session data of unique name */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                const char *unique_name;

                util_broker_connect(broker, &bus);

                r = sd_bus_get_unique_name(bus, &unique_name);
                c_assert(r >= 0);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "GetAdtAuditSessionData", &error, NULL,
                                       "s", unique_name);
                c_assert(r < 0);
                c_assert(!strcmp(error.name, "org.freedesktop.DBus.Error.AdtAuditDataUnknown"));
        }

        /* get adt audit session data of name that does not exist */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                util_broker_connect(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "GetAdtAuditSessionData", &error, NULL,
                                       "s", "com.example.foo");
                c_assert(r < 0);
                c_assert(!strcmp(error.name, "org.freedesktop.DBus.Error.NameHasNoOwner"));
        }

        /* get adt audit session data of invalid name */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                util_broker_connect(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "GetAdtAuditSessionData", &error, NULL,
                                       "s", "org");
                c_assert(r < 0);
                c_assert(!strcmp(error.name, "org.freedesktop.DBus.Error.NameHasNoOwner"));
        }

        util_broker_terminate(broker);
}

static void test_get_id(void) {
        _c_cleanup_(util_broker_freep) Broker *broker = NULL;
        int r;

        util_broker_new(&broker);
        util_broker_spawn(broker);

        /* get bus id before registering */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                util_broker_connect_raw(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "GetId", &error, NULL,
                                       "");
                c_assert(!strcmp(error.name, "org.freedesktop.DBus.Error.AccessDenied"));
        }

        /* get the bus id and verify that it is on the right format */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
                const char *id;

                util_broker_connect(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "GetId", NULL, &reply,
                                       "");
                c_assert(r >= 0);

                r = sd_bus_message_read(reply, "s", &id);
                c_assert(r >= 0);
                c_assert(strlen(id) == 32);

                for (size_t i = 0; i < strlen(id); ++i)
                        c_assert((id[i] >= '0' && id[i] <= '9') ||
                               (id[i] >= 'a' && id[i] <= 'f'));
        }

        util_broker_terminate(broker);
}

static void test_introspect(void) {
        _c_cleanup_(util_broker_freep) Broker *broker = NULL;
        int r;

        util_broker_new(&broker);
        util_broker_spawn(broker);

        /* get introspection data before registering */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                util_broker_connect_raw(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus.Introspectable",
                                       "Introspect", &error, NULL,
                                       "s", "com.example.foo");
                c_assert(!strcmp(error.name, "org.freedesktop.DBus.Error.AccessDenied"));
        }

        /* get introspection data, and verify that it is a non-empty string */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
                const char *introspection;

                util_broker_connect(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus.Introspectable",
                                       "Introspect", NULL, &reply,
                                       "");
                c_assert(r >= 0);

                r = sd_bus_message_read(reply, "s", &introspection);
                c_assert(r >= 0);
                c_assert(strlen(introspection) > 0);
        }

        util_broker_terminate(broker);
}

static void test_reload_config(void) {
        _c_cleanup_(util_broker_freep) Broker *broker = NULL;
        int r;

        util_broker_new(&broker);
        util_broker_spawn(broker);

        /* reload config before registering */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                util_broker_connect_raw(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "ReloadConfig", &error, NULL,
                                       "");
                c_assert(!strcmp(error.name, "org.freedesktop.DBus.Error.AccessDenied"));
        }

        /* call ReloadConfig and block until it succeeds */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;

                util_broker_connect(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "ReloadConfig", NULL, NULL,
                                       "");
                c_assert(r >= 0);
        }

        util_broker_terminate(broker);
}

static void test_become_monitor(void) {
        _c_cleanup_(util_broker_freep) Broker *broker = NULL;
        int r;

        util_broker_new(&broker);
        util_broker_spawn(broker);

        /* become monitor before registering */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                util_broker_connect_raw(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus.Monitoring",
                                       "BecomeMonitor", &error, NULL,
                                       "asu", 0);
                c_assert(!strcmp(error.name, "org.freedesktop.DBus.Error.AccessDenied"));
        }

        /* become monitor */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;

                util_broker_connect(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus.Monitoring",
                                       "BecomeMonitor", NULL, NULL,
                                       "asu", 0, 0);
                c_assert(r >= 0);

                /* calling any method after having become monitor forcibly disconnects the peer */
                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "Hello", NULL, NULL,
                                       "");
                c_assert(r == -ECONNRESET);
        }

        /* become monitor with a match duplicate */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;

                util_broker_connect(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus.Monitoring",
                                       "BecomeMonitor", NULL, NULL,
                                       "asu",
                                       2, "sender=com.example.test", "sender=com.example.test",
                                       0);
                c_assert(r >= 0);
        }

        util_broker_terminate(broker);
}

static void test_ping(void) {
        _c_cleanup_(util_broker_freep) Broker *broker = NULL;
        int r;

        util_broker_new(&broker);
        util_broker_spawn(broker);

        /* ping before registering */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                util_broker_connect_raw(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus.Peer",
                                       "Ping", &error, NULL,
                                       "");
                c_assert(!strcmp(error.name, "org.freedesktop.DBus.Error.AccessDenied"));
        }

        /* ping-pong */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;

                util_broker_connect(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus.Peer",
                                       "Ping", NULL, NULL,
                                       "");
                c_assert(r >= 0);
        }

        util_broker_terminate(broker);
}

static void test_get_machine_id(void) {
        _c_cleanup_(util_broker_freep) Broker *broker = NULL;
        int r;

        util_broker_new(&broker);
        util_broker_spawn(broker);

        /* get machine id before registering */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                util_broker_connect_raw(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus.Peer",
                                       "GetMachineId", &error, NULL,
                                       "");
                c_assert(!strcmp(error.name, "org.freedesktop.DBus.Error.AccessDenied"));
        }

        /* get the machine id and verify that it is on the right format */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
                const char *id;

                util_broker_connect(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus.Peer",
                                       "GetMachineId", NULL, &reply,
                                       "");
                c_assert(r >= 0);

                r = sd_bus_message_read(reply, "s", &id);
                c_assert(r >= 0);
                c_assert(strlen(id) == 32);

                for (size_t i = 0; i < strlen(id); ++i)
                        c_assert((id[i] >= '0' && id[i] <= '9') ||
                               (id[i] >= 'a' && id[i] <= 'f'));
        }

        util_broker_terminate(broker);
}

static void test_verify_property_features(sd_bus_message *message) {
        bool selinux = false;
        int r;

        r = sd_bus_message_enter_container(message, 'v', "as");
        c_assert(r >= 0);

        r = sd_bus_message_enter_container(message, 'a', "s");
        c_assert(r >= 0);

        while (!sd_bus_message_at_end(message, false)) {
                const char *feature;

                r = sd_bus_message_read(message, "s", &feature);
                c_assert(r >= 0);

                if (strcmp(feature, "SELinux") == 0)
                        selinux = true;
        }

        r = sd_bus_message_exit_container(message);
        c_assert(r >= 0);

        r = sd_bus_message_exit_container(message);
        c_assert(r >= 0);

        c_assert(selinux == bus_selinux_is_enabled());
}

static void test_verify_property_interfaces(sd_bus_message *message) {
        bool monitoring = false;
        int r;

        r = sd_bus_message_enter_container(message, 'v', "as");
        c_assert(r >= 0);

        r = sd_bus_message_enter_container(message, 'a', "s");
        c_assert(r >= 0);

        while (!sd_bus_message_at_end(message, false)) {
                const char *interface;

                r = sd_bus_message_read(message, "s", &interface);
                c_assert(r >= 0);

                if (strcmp(interface, "org.freedesktop.DBus.Monitoring") == 0)
                        monitoring = true;
        }

        r = sd_bus_message_exit_container(message);
        c_assert(r >= 0);

        r = sd_bus_message_exit_container(message);
        c_assert(r >= 0);

        c_assert(monitoring);
}

static void test_properties(void) {
        _c_cleanup_(util_broker_freep) Broker *broker = NULL;
        int r;

        util_broker_new(&broker);
        util_broker_spawn(broker);

        /* get features */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;

                util_broker_connect(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus.Properties",
                                       "Get", NULL, &reply,
                                       "ss", "org.freedesktop.DBus", "Features");
                c_assert(r >= 0);

                test_verify_property_features(reply);
        }

        /* get interfaces */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;

                util_broker_connect(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus.Properties",
                                       "Get", NULL, &reply,
                                       "ss", "org.freedesktop.DBus", "Interfaces");
                c_assert(r >= 0);

                test_verify_property_interfaces(reply);
        }

        /* set features */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                util_broker_connect(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus.Properties",
                                       "Set", &error, NULL,
                                       "ssv", "org.freedesktop.DBus", "Features", "as", 1, "Foo");
                c_assert(r < 0);
                c_assert(strcmp(error.name, "org.freedesktop.DBus.Error.PropertyReadOnly") == 0);
        }

        /* set interfaces */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                util_broker_connect(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus.Properties",
                                       "Set", &error, NULL,
                                       "ssv", "org.freedesktop.DBus", "Interfaces", "as", 1, "Foo");
                c_assert(r < 0);
                c_assert(strcmp(error.name, "org.freedesktop.DBus.Error.PropertyReadOnly") == 0);
        }

        /* get all */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
                bool features = false, interfaces = false;

                util_broker_connect(broker, &bus);

                r = sd_bus_call_method(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus.Properties",
                                       "GetAll", NULL, &reply,
                                       "s", "org.freedesktop.DBus");
                c_assert(r >= 0);

                r = sd_bus_message_enter_container(reply, 'a', "{sv}");
                c_assert(r >= 0);

                while ((r = sd_bus_message_enter_container(reply, 'e', "sv")) > 0) {
                        const char *property;

                        r = sd_bus_message_read(reply, "s", &property);
                        c_assert(r >= 0);

                        if (strcmp(property, "Features") == 0) {
                                test_verify_property_features(reply);
                                features = true;
                        } else if (strcmp(property, "Interfaces") == 0) {
                                test_verify_property_interfaces(reply);
                                interfaces = true;
                        } else {
                                r = sd_bus_message_skip(reply, "v");
                                c_assert(r >= 0);
                        }

                        r = sd_bus_message_exit_container(reply);
                        c_assert(r >= 0);
                }

                r = sd_bus_message_exit_container(reply);
                c_assert(r >= 0);

                c_assert(features && interfaces);
        }

        util_broker_terminate(broker);
}

static void test_no_destination(void) {
        _c_cleanup_(util_broker_freep) Broker *broker = NULL;
        int r;

        util_broker_new(&broker);
        util_broker_spawn(broker);

        /* don't provide a destination, verify that the driver answers on the Peer interface regardless */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_message_unrefp) sd_bus_message *message = NULL;

                util_broker_connect(broker, &bus);

                r = sd_bus_message_new_method_call(bus, &message, NULL, "/org/freedestkop/DBus",
                                                   "org.freedesktop.DBus.Peer", "Ping");
                c_assert(r >= 0);

                r = sd_bus_call(bus, message, 0, NULL, NULL);
                c_assert(r >= 0);
        }

        /* however, it won't answer on any of the other interfaces */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_message_unrefp) sd_bus_message *message = NULL;
                _c_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                util_broker_connect(broker, &bus);

                r = sd_bus_message_new_method_call(bus, &message, NULL, "/org/freedestkop/DBus",
                                                   "org.freedesktop.DBus", "GetId");
                c_assert(r >= 0);

                r = sd_bus_call(bus, message, 0, &error, NULL);
                c_assert(r < 0);
                c_assert(strcmp(error.name, "org.freedesktop.DBus.Error.UnknownMethod") == 0);
        }

        util_broker_terminate(broker);
}

static void test_stats(void) {
        _c_cleanup_(util_broker_freep) Broker *broker = NULL;
        int r;

        util_broker_new(&broker);
        util_broker_spawn(broker);

        /* test the integrity of the fdo.Debug.Stats interface */
        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
                _c_cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;

                util_broker_connect(broker, &bus);

                r = sd_bus_call_method(bus,
                                       "org.freedesktop.DBus",
                                       "/org/freedesktop/DBus",
                                       "org.freedesktop.DBus.Debug.Stats",
                                       "GetStats",
                                       NULL,
                                       &reply,
                                       "");
                c_assert(r >= 0);

                r = sd_bus_message_enter_container(reply, 'a', "{sv}");
                c_assert(r >= 0);

                while ((r = sd_bus_message_enter_container(reply, 'e', "sv")) > 0) {
                        const char *stat;

                        r = sd_bus_message_read(reply, "s", &stat);
                        c_assert(r >= 0);

                        if (strcmp(stat, "org.bus1.DBus.Debug.Stats.PeerAccounting") == 0) {
                                r = sd_bus_message_enter_container(reply, 'v', "a(sa{sv}a{su})");
                                c_assert(r >= 0);

                                r = sd_bus_message_enter_container(reply, 'a', "(sa{sv}a{su})");
                                c_assert(r >= 0);

                                while ((r = sd_bus_message_enter_container(reply, 'r', "sa{sv}a{su}")) > 0) {
                                        r = sd_bus_message_skip(reply, "sa{sv}a{su}");
                                        c_assert(r >= 0);

                                        r = sd_bus_message_exit_container(reply);
                                        c_assert(r >= 0);
                                }

                                r = sd_bus_message_exit_container(reply);
                                c_assert(r >= 0);

                                r = sd_bus_message_exit_container(reply);
                                c_assert(r >= 0);
                        } else if (strcmp(stat, "org.bus1.DBus.Debug.Stats.UserAccounting") == 0) {
                                r = sd_bus_message_enter_container(reply, 'v', "a(ua(suu)a{ua{su}})");
                                c_assert(r >= 0);

                                r = sd_bus_message_enter_container(reply, 'a', "(ua(suu)a{ua{su}})");
                                c_assert(r >= 0);

                                while ((r = sd_bus_message_enter_container(reply, 'r', "ua(suu)a{ua{su}}")) > 0) {
                                        r = sd_bus_message_skip(reply, "ua(suu)a{ua{su}}");
                                        c_assert(r >= 0);

                                        r = sd_bus_message_exit_container(reply);
                                        c_assert(r >= 0);
                                }

                                r = sd_bus_message_exit_container(reply);
                                c_assert(r >= 0);

                                r = sd_bus_message_exit_container(reply);
                                c_assert(r >= 0);
                        } else if (strcmp(stat, "Serial") == 0 ||
                                   strcmp(stat, "ActiveConnections") == 0 ||
                                   strcmp(stat, "IncompleteConnections") == 0 ||
                                   strcmp(stat, "BusNames") == 0 ||
                                   strcmp(stat, "PeakBusNames") == 0 ||
                                   strcmp(stat, "PeakBusNamesPerConnection") == 0 ||
                                   strcmp(stat, "MatchRules") == 0 ||
                                   strcmp(stat, "PeakMatchRules") == 0 ||
                                   strcmp(stat, "PeakMatchRulesPerConnection") == 0) {
                                r = sd_bus_message_enter_container(reply, 'v', "u");
                                c_assert(r >= 0);

                                r = sd_bus_message_skip(reply, "u");
                                c_assert(r >= 0);

                                r = sd_bus_message_exit_container(reply);
                                c_assert(r >= 0);
                        } else {
                                r = sd_bus_message_skip(reply, "v");
                                c_assert(r >= 0);
                        }

                        r = sd_bus_message_exit_container(reply);
                        c_assert(r >= 0);
                }

                r = sd_bus_message_exit_container(reply);
                c_assert(r >= 0);
        }

        util_broker_terminate(broker);
}

int main(int argc, char **argv) {
        test_unknown();
        test_hello();
        test_request_name();
        test_release_name();
        test_get_name_owner();
        test_name_has_owner();
        test_start_service_by_name();
        test_update_activation_environment();
        test_list_names();
        test_list_activatable_names();
        test_add_match();
        test_remove_match();
        test_list_queued_owners();
        test_get_connection_unix_user();
        test_get_connection_unix_process_id();
        test_get_connection_credentials();
        test_get_connection_selinux_security_context();
        test_get_adt_audit_session_data();
        test_get_id();
        test_reload_config();
        test_introspect();
        test_become_monitor();
        test_ping();
        test_get_machine_id();
        test_properties();
        test_no_destination();
        test_stats();

        return 0;
}
