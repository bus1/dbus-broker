/*
 * Reexecute Tests
 */

#undef NDEBUG
#include <c-stdaux.h>
#include <systemd/sd-bus.h>
#include <unistd.h>
#include "util-broker.h"
#include "util/string.h"

#define PATH_LENGTH_MAX 4096
#define TEST_ARG_MAX 12

static void test_send_reexecute() {
        Broker *broker = NULL;
        _c_cleanup_(sd_bus_flush_close_unrefp) sd_bus *test_bus = NULL, *listener_bus = NULL, *cmd_bus = NULL;
        _c_cleanup_(sd_bus_message_unrefp) sd_bus_message *listener_message = NULL;
        _c_cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        const char *reply_str = NULL, *unique_name = NULL, *owner = NULL;
        int r;

        util_broker_new(&broker);
        broker->test_reexec = true;
        util_broker_spawn(broker);

        pid_t pid = fork();
        if (pid) {
                /* Add Listener. */
                create_broker_listener(broker);
                /* Wait 1s to make sure broker has reexecuted. */
                sleep(1);

                r = sd_bus_new(&listener_bus);
                c_assert(r >= 0);

                r = sd_bus_set_fd(listener_bus, broker->lc_fd, broker->lc_fd);
                c_assert(r >= 0);

                r = sd_bus_start(listener_bus);
                c_assert(r >= 0);

                r = sd_bus_message_new_method_call(listener_bus, &listener_message, NULL,
                                                   "/org/bus1/DBus/Broker", "org.bus1.DBus.Broker", "AddListener");
                c_assert(r >= 0);

                r = sd_bus_message_append(listener_message, "oh", "/org/bus1/DBus/Listener/0", broker->listener_fd);
                c_assert(r >= 0);

                r = util_append_policy(listener_message);
                c_assert(r >= 0);

                r = sd_bus_call(listener_bus, listener_message, -1, NULL, NULL);
                c_assert(r >= 0);

                return 0;
        }

        /* Request name before reexecuting. */
        {
                util_broker_connect(broker, &test_bus);
                r = sd_bus_get_unique_name(test_bus, &unique_name);
                c_assert(r >= 0);
                r = sd_bus_call_method(test_bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "RequestName", NULL, NULL, "su", "com.example.foo", 0);
                c_assert(r >= 0);
        }

        /* Make broker reexecute. */
        {
                util_broker_connect(broker, &cmd_bus);
                r = sd_bus_call_method(cmd_bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "Reexecute", NULL, &reply, "");
                c_assert(r >= 0);

                r = sd_bus_message_read(reply, "s", &reply_str);
                c_assert(r >= 0);
                c_assert(!strcmp(reply_str, "OK"));

                sd_bus_flush_close_unref(cmd_bus);
        }

        /* GetNameOwner after reexecuting. */
        {
                r = sd_bus_call_method(test_bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                       "GetNameOwner", NULL, &reply, "s", "com.example.foo");
                c_assert(r >= 0);

                r = sd_bus_message_read(reply, "s", &owner);
                c_assert(r >= 0);
                c_assert(!strcmp(owner, unique_name));
        }

        c_assert(r >= 0);
}

static void test_generate_args_string() {
        char *args[TEST_ARG_MAX];
        for (int i = 0; i < TEST_ARG_MAX; i++) {
                args[i] = NULL;
        }
        int i = 0;
        generate_args_string(false, args, TEST_ARG_MAX, &i, "--log", "1");
        c_assert(i == 0 && args[i] == NULL);
        generate_args_string(true, args, TEST_ARG_MAX, &i, "--controller", "2");
        c_assert(i == 2 && !strcmp(args[0], "--controller") && !strcmp(args[1], "2"));
        generate_args_string(true, args, TEST_ARG_MAX, &i, "--machine-id", "3");
        c_assert(i == 4 && !strcmp(args[2], "--machine-id") && !strcmp(args[3], "3"));
        generate_args_string(true, args, TEST_ARG_MAX, &i, "--max-bytes", "123456");
        c_assert(i == 6 && !strcmp(args[4], "--max-bytes") && !strcmp(args[5], "123456"));
        generate_args_string(true, args, TEST_ARG_MAX, &i, "--max-fds", "12");
        c_assert(i == 8 && !strcmp(args[6], "--max-fds") && !strcmp(args[7], "12"));
        generate_args_string(true, args, TEST_ARG_MAX, &i, "--max-matches", "12345abcde");
        c_assert(i == 10 && !strcmp(args[8], "--max-matches") && !strcmp(args[9], "12345abcde"));
        generate_args_string(true, args, TEST_ARG_MAX, &i, "--reexec", "13");
        c_assert(i == 10 && args[10] == NULL && args[11] == NULL);
}

int main(int argc, char **argv) {
        test_generate_args_string();
        /* Reexecute can only be run under privileged user */
        if (getuid() == 0)
                test_send_reexecute();
        return 0;
}
