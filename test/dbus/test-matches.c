/*
 * Client Lifetime Tests
 */

#undef NDEBUG
#include <c-stdaux.h>
#include <stdlib.h>
#include "util-broker.h"

static void test_wildcard(void) {
        _c_cleanup_(util_broker_freep) Broker *broker = NULL;
        _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *sender = NULL;
        _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *receiver = NULL;
        int r;

        util_broker_new(&broker);
        util_broker_spawn(broker);

        util_broker_connect(broker, &sender);
        util_broker_connect(broker, &receiver);

        r = sd_bus_call_method(receiver, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "AddMatch", NULL, NULL,
                               "s", "");
        c_assert(r >= 0);

        r = sd_bus_emit_signal(sender, "/org/example", "org.example", "Foo", "");
        c_assert(r >= 0);

        util_broker_consume_signal(receiver, "org.example", "Foo");

        util_broker_terminate(broker);
}

static void test_unique_name(void) {
        _c_cleanup_(util_broker_freep) Broker *broker = NULL;
        _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *sender = NULL;
        _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *receiver = NULL;
        _c_cleanup_(c_freep) char *match = NULL;
        const char *unique_name;
        int r;

        util_broker_new(&broker);
        util_broker_spawn(broker);

        util_broker_connect(broker, &sender);
        util_broker_connect(broker, &receiver);

        r = sd_bus_get_unique_name(sender, &unique_name);
        c_assert(r >= 0);

        r = asprintf(&match, "sender=%s", unique_name);
        c_assert(r >= 0);

        r = sd_bus_call_method(receiver, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "AddMatch", NULL, NULL,
                               "s", match);
        c_assert(r >= 0);

        r = sd_bus_emit_signal(sender, "/org/example", "org.example", "Foo", "");
        c_assert(r >= 0);

        util_broker_consume_signal(receiver, "org.example", "Foo");

        util_broker_terminate(broker);
}

static void test_well_known_name(void) {
        _c_cleanup_(util_broker_freep) Broker *broker = NULL;
        _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *dummy = NULL;
        _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *sender = NULL;
        _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *receiver = NULL;
        int r;

        util_broker_new(&broker);
        util_broker_spawn(broker);

        util_broker_connect(broker, &dummy);
        util_broker_connect(broker, &sender);
        util_broker_connect(broker, &receiver);

        r = sd_bus_call_method(dummy, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "RequestName", NULL, NULL,
                               "su", "com.example.foo", 0);
        c_assert(r >= 0);

        r = sd_bus_call_method(sender, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "RequestName", NULL, NULL,
                               "su", "com.example.foo", 0);
        c_assert(r >= 0);

        r = sd_bus_call_method(sender, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "RequestName", NULL, NULL,
                               "su", "com.example.bar", 0);
        c_assert(r >= 0);

        r = sd_bus_call_method(receiver, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "AddMatch", NULL, NULL,
                               "s", "sender=com.example.foo");
        c_assert(r >= 0);

        r = sd_bus_call_method(receiver, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "AddMatch", NULL, NULL,
                               "s", "sender=com.example.bar,interface=org.example.bar");
        c_assert(r >= 0);

        r = sd_bus_emit_signal(sender, "/org/example", "org.example", "Foo", "");
        c_assert(r >= 0);

        r = sd_bus_emit_signal(sender, "/org/example", "org.example.bar", "Bar", "");
        c_assert(r >= 0);

        util_broker_consume_signal(receiver, "org.example.bar", "Bar");

        util_broker_terminate(broker);
}

static void test_driver(void) {
        _c_cleanup_(util_broker_freep) Broker *broker = NULL;
        _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *receiver = NULL;
        int r;

        util_broker_new(&broker);
        util_broker_spawn(broker);

        util_broker_connect(broker, &receiver);

        r = sd_bus_call_method(receiver, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "AddMatch", NULL, NULL,
                               "s", "sender=org.freedesktop.DBus");
        c_assert(r >= 0);

        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *dummy = NULL;

                util_broker_connect(broker, &dummy);
        }

        util_broker_consume_signal(receiver, "org.freedesktop.DBus", "NameOwnerChanged");
        util_broker_consume_signal(receiver, "org.freedesktop.DBus", "NameOwnerChanged");

        util_broker_terminate(broker);
}

static void test_noc_wildcard(void) {
        _c_cleanup_(util_broker_freep) Broker *broker = NULL;
        _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *receiver = NULL;
        int r;

        util_broker_new(&broker);
        util_broker_spawn(broker);

        util_broker_connect(broker, &receiver);

        r = sd_bus_call_method(receiver, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "AddMatch", NULL, NULL,
                               "s", "sender=org.freedesktop.DBus,member=NameOwnerChanged");
        c_assert(r >= 0);

        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *dummy = NULL;

                util_broker_connect(broker, &dummy);
        }

        util_broker_consume_signal(receiver, "org.freedesktop.DBus", "NameOwnerChanged");
        util_broker_consume_signal(receiver, "org.freedesktop.DBus", "NameOwnerChanged");

        util_broker_terminate(broker);
}

static void test_noc_unique(void) {
        _c_cleanup_(util_broker_freep) Broker *broker = NULL;
        sd_bus *dummy; /* explicitly cleaned up below */
        _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *receiver = NULL;
        _c_cleanup_(c_freep) char *match = NULL;
        const char *unique_name;
        int r;

        util_broker_new(&broker);
        util_broker_spawn(broker);

        util_broker_connect(broker, &dummy);
        util_broker_connect(broker, &receiver);

        r = sd_bus_get_unique_name(dummy, &unique_name);
        c_assert(r >= 0);

        r = asprintf(&match, "sender=org.freedesktop.DBus,member=NameOwnerChanged,arg0=%s", unique_name);
        c_assert(r >= 0);

        r = sd_bus_call_method(receiver, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "AddMatch", NULL, NULL,
                               "s", match);
        c_assert(r >= 0);

        sd_bus_flush_close_unref(dummy);

        util_broker_consume_signal(receiver, "org.freedesktop.DBus", "NameOwnerChanged");

        util_broker_terminate(broker);
}

static void test_noc_well_known(void) {
        _c_cleanup_(util_broker_freep) Broker *broker = NULL;
        _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *dummy = NULL;
        _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *receiver = NULL;
        int r;

        util_broker_new(&broker);
        util_broker_spawn(broker);

        util_broker_connect(broker, &dummy);
        util_broker_connect(broker, &receiver);

        r = sd_bus_call_method(receiver, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "AddMatch", NULL, NULL,
                               "s", "sender=org.freedesktop.DBus,member=NameOwnerChanged,arg0=com.example.foo");
        c_assert(r >= 0);

        r = sd_bus_call_method(dummy, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "RequestName", NULL, NULL,
                               "su", "com.example.foo", 0);
        c_assert(r >= 0);

        r = sd_bus_call_method(dummy, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "ReleaseName", NULL, NULL,
                               "s", "com.example.foo");
        c_assert(r >= 0);

        util_broker_consume_signal(receiver, "org.freedesktop.DBus", "NameOwnerChanged");
        util_broker_consume_signal(receiver, "org.freedesktop.DBus", "NameOwnerChanged");

        util_broker_terminate(broker);
}

static void test_noc_driver(void) {
        _c_cleanup_(util_broker_freep) Broker *broker = NULL;
        _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *dummy = NULL;
        _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *receiver = NULL;
        int r;

        util_broker_new(&broker);
        util_broker_spawn(broker);

        util_broker_connect(broker, &dummy);
        util_broker_connect(broker, &receiver);

        r = sd_bus_call_method(receiver, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "AddMatch", NULL, NULL,
                               "s", "sender=org.freedesktop.DBus,member=NameOwnerChanged,arg0=org.freedesktop.DBus");
        c_assert(r >= 0);

        /*
         * This cannot be triggered, but make sure the implementation does not choke on this
         * special name.
         */
        util_broker_terminate(broker);
}

int main(int argc, char **argv) {
        test_wildcard();
        test_unique_name();
        test_well_known_name();
        test_driver();
        test_noc_wildcard();
        test_noc_unique();
        test_noc_well_known();
        test_noc_driver();
}
