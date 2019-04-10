/*
 * Client Lifetime Tests
 */

#undef NDEBUG
#include <c-stdaux.h>
#include <stdlib.h>
#include "util-broker.h"

static void test_dummy(void) {
        _c_cleanup_(util_broker_freep) Broker *broker = NULL;
        _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *monitor = NULL;

        util_broker_new(&broker);
        util_broker_spawn(broker);

        util_broker_connect_monitor(broker, &monitor);
        util_broker_terminate(broker);
}

static void test_client1(void) {
        _c_cleanup_(util_broker_freep) Broker *broker = NULL;
        _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *monitor = NULL;

        util_broker_new(&broker);
        util_broker_spawn(broker);

        util_broker_connect_monitor(broker, &monitor);

        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;

                util_broker_connect(broker, &bus);
        }

        util_broker_consume_method_call(monitor, "org.freedesktop.DBus", "Hello");
        util_broker_consume_method_return(monitor);
        util_broker_consume_signal(monitor, "org.freedesktop.DBus", "NameOwnerChanged");
        util_broker_consume_signal(monitor, "org.freedesktop.DBus", "NameAcquired");

        util_broker_consume_signal(monitor, "org.freedesktop.DBus", "NameLost");
        util_broker_consume_signal(monitor, "org.freedesktop.DBus", "NameOwnerChanged");

        util_broker_terminate(broker);
}

static void test_client2(void) {
        _c_cleanup_(util_broker_freep) Broker *broker = NULL;
        _c_cleanup_(sd_bus_unrefp) sd_bus *bus = NULL;

        util_broker_new(&broker);
        util_broker_spawn(broker);

        util_broker_connect(broker, &bus);
        util_broker_disconnect(bus);

        util_broker_terminate(broker);
}

static void test_monitor(void) {
        _c_cleanup_(util_broker_freep) Broker *broker = NULL;
        _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *monitor = NULL;

        util_broker_new(&broker);
        util_broker_spawn(broker);

        util_broker_connect_monitor(broker, &monitor);

        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;

                util_broker_connect_monitor(broker, &bus);
        }

        util_broker_consume_method_call(monitor, "org.freedesktop.DBus", "Hello");
        util_broker_consume_method_return(monitor);
        util_broker_consume_signal(monitor, "org.freedesktop.DBus", "NameOwnerChanged");
        util_broker_consume_signal(monitor, "org.freedesktop.DBus", "NameAcquired");

        util_broker_consume_method_call(monitor, "org.freedesktop.DBus.Monitoring", "BecomeMonitor");
        util_broker_consume_method_return(monitor);
        util_broker_consume_signal(monitor, "org.freedesktop.DBus", "NameLost");
        util_broker_consume_signal(monitor, "org.freedesktop.DBus", "NameOwnerChanged");

        util_broker_terminate(broker);
}

static void test_names(void) {
        _c_cleanup_(util_broker_freep) Broker *broker = NULL;
        _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *monitor = NULL;
        int r;

        util_broker_new(&broker);
        util_broker_spawn(broker);

        util_broker_connect_monitor(broker, &monitor);

        {
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus1 = NULL;
                _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus2 = NULL;

                util_broker_connect(broker, &bus1);

                r = sd_bus_call_method(bus1, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "RequestName", NULL, NULL,
                                       "su", "com.example.foo", 0);
                c_assert(r >= 0);

                util_broker_connect(broker, &bus2);

                r = sd_bus_call_method(bus2, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "RequestName", NULL, NULL,
                                       "su", "com.example.foo", 0);
                c_assert(r >= 0);

                r = sd_bus_call_method(bus1, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "ReleaseName", NULL, NULL,
                                       "s", "com.example.foo");
                c_assert(r >= 0);
        }

        util_broker_consume_method_call(monitor, "org.freedesktop.DBus", "Hello");
        util_broker_consume_method_return(monitor);
        util_broker_consume_signal(monitor, "org.freedesktop.DBus", "NameOwnerChanged");
        util_broker_consume_signal(monitor, "org.freedesktop.DBus", "NameAcquired");

        util_broker_consume_method_call(monitor, "org.freedesktop.DBus", "RequestName");
        util_broker_consume_signal(monitor, "org.freedesktop.DBus", "NameOwnerChanged");
        util_broker_consume_signal(monitor, "org.freedesktop.DBus", "NameAcquired");
        util_broker_consume_method_return(monitor);

        util_broker_consume_method_call(monitor, "org.freedesktop.DBus", "Hello");
        util_broker_consume_method_return(monitor);
        util_broker_consume_signal(monitor, "org.freedesktop.DBus", "NameOwnerChanged");
        util_broker_consume_signal(monitor, "org.freedesktop.DBus", "NameAcquired");

        util_broker_consume_method_call(monitor, "org.freedesktop.DBus", "RequestName");
        util_broker_consume_method_return(monitor);

        util_broker_consume_method_call(monitor, "org.freedesktop.DBus", "ReleaseName");
        util_broker_consume_signal(monitor, "org.freedesktop.DBus", "NameLost");
        util_broker_consume_signal(monitor, "org.freedesktop.DBus", "NameOwnerChanged");
        util_broker_consume_signal(monitor, "org.freedesktop.DBus", "NameAcquired");
        util_broker_consume_method_return(monitor);

        util_broker_consume_signal(monitor, "org.freedesktop.DBus", "NameLost");
        util_broker_consume_signal(monitor, "org.freedesktop.DBus", "NameOwnerChanged");
        util_broker_consume_signal(monitor, "org.freedesktop.DBus", "NameLost");
        util_broker_consume_signal(monitor, "org.freedesktop.DBus", "NameOwnerChanged");
        util_broker_consume_signal(monitor, "org.freedesktop.DBus", "NameLost");
        util_broker_consume_signal(monitor, "org.freedesktop.DBus", "NameOwnerChanged");

        util_broker_terminate(broker);
}

int main(int argc, char **argv) {
        test_dummy();
        test_client1();
        test_client2();
        test_monitor();
        test_names();
}
