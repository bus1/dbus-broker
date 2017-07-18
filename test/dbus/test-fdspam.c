/*
 * Verify FD Spam Protection
 */

#include <c-dvar.h>
#include <c-dvar-type.h>
#include <c-macro.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include "dbus/connection.h"
#include "dbus/message.h"
#include "dbus/protocol.h"
#include "dbus/socket.h"
#include "util/dispatch.h"
#include "util/fdlist.h"
#include "util-broker.h"

static char test_unique[256];

static Message *test_hello(void) {
        static const CDVarType type[] = {
                C_DVAR_T_INIT(
                        C_DVAR_T_TUPLE2(
                                C_DVAR_T_TUPLE7(
                                        C_DVAR_T_y,
                                        C_DVAR_T_y,
                                        C_DVAR_T_y,
                                        C_DVAR_T_y,
                                        C_DVAR_T_u,
                                        C_DVAR_T_u,
                                        C_DVAR_T_ARRAY(
                                                C_DVAR_T_TUPLE2(
                                                        C_DVAR_T_y,
                                                        C_DVAR_T_v
                                                )
                                        )
                                ),
                                C_DVAR_T_TUPLE0
                        )
                )
        };
        _c_cleanup_(c_dvar_deinit) CDVar v = C_DVAR_INIT;
        Message *m = NULL;
        size_t n_data;
        void *data;
        int r;

        c_dvar_begin_write(&v, type, 1);

        c_dvar_write(&v, "((yyyyuu[(y<s>)(y<o>)(y<s>)])())",
                     c_dvar_is_big_endian(&v) ? 'B' : 'l',
                     DBUS_MESSAGE_TYPE_METHOD_CALL,
                     0, 1, 0, 1,
                     DBUS_MESSAGE_FIELD_DESTINATION, c_dvar_type_s, "org.freedesktop.DBus",
                     DBUS_MESSAGE_FIELD_PATH, c_dvar_type_o, "/org/freedesktop/DBus",
                     DBUS_MESSAGE_FIELD_MEMBER, c_dvar_type_s, "Hello");

        r = c_dvar_end_write(&v, &data, &n_data);
        assert(!r);

        r = message_new_outgoing(&m, data, n_data);
        assert(!r);

        return m;
}

static Message *test_message(size_t n_fds, const char *dst) {
        static const CDVarType type[] = {
                C_DVAR_T_INIT(
                        C_DVAR_T_TUPLE2(
                                C_DVAR_T_TUPLE7(
                                        C_DVAR_T_y,
                                        C_DVAR_T_y,
                                        C_DVAR_T_y,
                                        C_DVAR_T_y,
                                        C_DVAR_T_u,
                                        C_DVAR_T_u,
                                        C_DVAR_T_ARRAY(
                                                C_DVAR_T_TUPLE2(
                                                        C_DVAR_T_y,
                                                        C_DVAR_T_v
                                                )
                                        )
                                ),
                                C_DVAR_T_TUPLE0
                        )
                )
        };
        _c_cleanup_(c_dvar_deinit) CDVar v = C_DVAR_INIT;
        Message *m = NULL;
        size_t n_data;
        void *data;
        int r;

        assert(strlen(dst) > 0);

        c_dvar_begin_write(&v, type, 1);

        c_dvar_write(&v, "((yyyyuu[(y<s>)(y<o>)(y<s>)(y<u>)])())",
                     c_dvar_is_big_endian(&v) ? 'B' : 'l',
                     DBUS_MESSAGE_TYPE_METHOD_CALL,
                     DBUS_HEADER_FLAG_NO_REPLY_EXPECTED,
                     1, 0, 2,
                     DBUS_MESSAGE_FIELD_DESTINATION, c_dvar_type_s, dst,
                     DBUS_MESSAGE_FIELD_PATH, c_dvar_type_o, "/",
                     DBUS_MESSAGE_FIELD_MEMBER, c_dvar_type_s, "Foobar",
                     DBUS_MESSAGE_FIELD_UNIX_FDS, c_dvar_type_u, n_fds);

        r = c_dvar_end_write(&v, &data, &n_data);
        assert(!r);

        r = message_new_outgoing(&m, data, n_data);
        assert(!r);

        if (n_fds > 0) {
                int fds[n_fds];

                memset(fds, 0, sizeof(fds));
                r = fdlist_new_with_fds(&m->fds, fds, n_fds);
                assert(!r);
        }

        return m;
}

static int test_dispatch_fn(DispatchFile *file, uint32_t events) {
        Connection *c = c_container_of(file, Connection, socket_file);
        int r;

        r = connection_dispatch(c, events);
        assert(!r);

        do {
                _c_cleanup_(message_unrefp) Message *m = NULL;

                r = connection_dequeue(c, &m);
                if (!r) {
                        if (!m)
                                break;

                        r = message_parse_metadata(m);
                        assert(!r);

                        if (m->metadata.fields.reply_serial == 1) {
                                strcpy(test_unique, m->metadata.args[0].value);
                                return DISPATCH_E_EXIT;
                        } else if (m->metadata.header.type == DBUS_MESSAGE_TYPE_METHOD_CALL &&
                                   m->metadata.header.serial == 2) {
                                if (m->metadata.fields.unix_fds <= 1)
                                        return DISPATCH_E_EXIT;
                        } else if (m->metadata.header.type == DBUS_MESSAGE_TYPE_ERROR) {
                                assert(!strcmp(m->metadata.fields.error_name,
                                               "org.freedesktop.DBus.Error.LimitsExceeded"));
                        } else {
                                assert(m->metadata.header.type == DBUS_MESSAGE_TYPE_SIGNAL);
                        }
                }
        } while (!r);

        if (r == CONNECTION_E_EOF) {
                connection_shutdown(c);
                return connection_is_running(c) ? 0 : DISPATCH_E_EXIT;
        }

        assert(!r);
        return 0;
}

static void test_fd_spam(void) {
        _c_cleanup_(util_broker_freep) Broker *broker = NULL;
        _c_cleanup_(dispatch_context_deinit) DispatchContext d1 = DISPATCH_CONTEXT_NULL(d1);
        _c_cleanup_(connection_deinit) Connection c = CONNECTION_NULL(c);
        _c_cleanup_(c_freep) char *sender = NULL;
        size_t i, j, n_fds = 0;
        int fds[512];
        int r, fd;

        /*
         * This test is a bit more elaborate and subtle. It verifies that
         * inflight FDs are correctly accounted by the broker. It does the
         * following:
         *
         *   * Spawn the broker with uid 1
         *   * Create a sender with uid 2
         *   * for i to n
         *       * Create destinations with uid 2
         *       * Send messages from the sender to this destination, all
         *         containing FDs.
         *         After each FD-message, send a roundtrip from the sender to
         *         itself to verify the queues are empty.
         *       * Do *NOT* dequeue those messages on the destination.
         *       * shutdown SHUT_RDWR on the destination, but keeping its
         *         buffers alive.
         *   * Create one more connection with uid 3
         *       * Make this connection send itself a message with FDs. Verify
         *         it is not dropped.
         *
         * In other words, what this test does is create a bunch of connections
         * that get file-descriptors queued by the daemon. However, we
         * carefully choose a very small amount of messages we queue on each,
         * such that those can all be queued in the kernel buffers. The broker
         * is hence no longer under buffer control. We then trick the broker
         * into thinking those clients were disconnected (which is not
         * necessary but an additional attack vector).
         *
         * Once we have all those connections with queued FDs, we create a 3rd
         * party client that is innocent and just tries to send a single FD.
         * This better goes through, otherwise the attacker with uid 2
         * succeeded in blocking all FD traffic.
         *
         * The underlying problem here is that the linux kernel accounts sent
         * FDs on the *SENDER* until they're dequeued by the receiver. Hence,
         * the broker is accounted for all FDs queued in *kernel-buffers* and
         * better tracks those and applies quotas. A single attacker should not
         * be able to exhaust the broker's inflight-FD limit that way.
         */

        /* create broker as uid 1 */
        {
                r = setresuid(1, 1, 0);
                assert(!r);

                util_broker_new(&broker);
                util_broker_spawn(broker);
        }

        /* create spammer as uid 2 */
        {
                r = setresuid(0, 0, 0);
                assert(!r);
                r = setresuid(2, 2, 0);
                assert(!r);

                r = dispatch_context_init(&d1);
                assert(!r);

                util_broker_connect_fd(broker, &fd);

                r = connection_init_client(&c, &d1, test_dispatch_fn, NULL, fd);
                assert(!r);

                r = connection_open(&c);
                assert(!r);
        }

        /* dispatch spammer till after Hello() */
        {
                _c_cleanup_(message_unrefp) Message *m = NULL;

                m = test_hello();
                r = connection_queue(&c, NULL, m);
                assert(!r);

                do {
                        r = dispatch_context_dispatch(&d1);
                        assert(!r || r == DISPATCH_E_EXIT);
                } while (!r);

                assert(connection_is_running(&c));

                assert(!strcmp(test_unique, ":1.0"));
                sender = strdup(test_unique);
                assert(sender);
        }

        /* create destinations and spam them */
        {
                for (i = 0; i < C_ARRAY_SIZE(fds); ++i) {
                        _c_cleanup_(dispatch_context_deinit) DispatchContext d2 = DISPATCH_CONTEXT_NULL(d2);
                        _c_cleanup_(connection_deinit) Connection dst = CONNECTION_NULL(dst);

                        /* connect client */
                        {
                                r = dispatch_context_init(&d2);
                                assert(!r);

                                util_broker_connect_fd(broker, &fds[i]);
                                ++n_fds;

                                r = connection_init_client(&dst, &d2, test_dispatch_fn, NULL, fds[i]);
                                assert(!r);

                                r = connection_open(&dst);
                                assert(!r);
                        }

                        /* fast-forward Hello() */
                        {
                                _c_cleanup_(message_unrefp) Message *m = NULL;

                                m = test_hello();
                                r = connection_queue(&dst, NULL, m);
                                assert(!r);

                                do {
                                        r = dispatch_context_dispatch(&d2);
                                        assert(!r || r == DISPATCH_E_EXIT);
                                } while (!r);

                                assert(connection_is_running(&dst));
                        }

                        /* send spam from @c to @dst */
                        {
                                _c_cleanup_(message_unrefp) Message *m1 = NULL, *m2 = NULL;

                                m1 = test_message(8, test_unique);
                                m2 = test_message(0, sender);

                                for (j = 0; j < 32; ++j) {
                                        r = connection_queue(&c, NULL, m1);
                                        assert(!r);
                                        r = connection_queue(&c, NULL, m2);
                                        assert(!r);

                                        do {
                                                r = dispatch_context_dispatch(&d1);
                                                assert(!r || r == DISPATCH_E_EXIT);
                                        } while (!r);

                                        assert(connection_is_running(&c));

                                        r = connection_dispatch(&c, EPOLLOUT);
                                        assert(!r);
                                }
                        }

                        /* shutdown @dst but keep alive */
                        {
                                r = shutdown(fds[i], SHUT_RDWR);
                                assert(!r);
                        }
                }
        }

        /* attempt a single non-fd method call on uid 3 */
        {
                _c_cleanup_(dispatch_context_deinit) DispatchContext d2 = DISPATCH_CONTEXT_NULL(d2);
                _c_cleanup_(c_closep) int fd2 = -1;
                _c_cleanup_(connection_deinit) Connection c2 = CONNECTION_NULL(c2);

                {
                        r = setresuid(0, 0, 0);
                        assert(!r);
                        r = setresuid(3, 3, 0);
                        assert(!r);

                        r = dispatch_context_init(&d2);
                        assert(!r);

                        util_broker_connect_fd(broker, &fd2);

                        r = connection_init_client(&c2, &d2, test_dispatch_fn, NULL, fd2);
                        assert(!r);

                        r = connection_open(&c2);
                        assert(!r);
                }

                /* dispatch till after Hello() */
                {
                        _c_cleanup_(message_unrefp) Message *m = NULL;

                        m = test_hello();
                        r = connection_queue(&c2, NULL, m);
                        assert(!r);

                        do {
                                r = dispatch_context_dispatch(&d2);
                                assert(!r || r == DISPATCH_E_EXIT);
                        } while (!r);

                        assert(connection_is_running(&c2));
                }

                /* dispatch single message with FD */
                {
                        _c_cleanup_(message_unrefp) Message *m = NULL;

                        m = test_message(1, test_unique);
                        r = connection_queue(&c2, NULL, m);
                        assert(!r);

                        do {
                                r = dispatch_context_dispatch(&d2);
                                assert(!r || r == DISPATCH_E_EXIT);
                        } while (!r);

                        assert(connection_is_running(&c2));
                }
        }

        /* run cleanup as root again */
        {
                r = setresuid(0, 0, 0);
                assert(!r);

                while (n_fds--)
                        c_close(fds[n_fds]);

                util_broker_terminate(broker);
        }
}

int main(int argc, char **argv) {
        /*
         * dbus-daemon(1) does not have sufficient protection against FD
         * spamming, hence we have to skip tests if running against it.
         *
         * Furthermore, for proper test validation we need to be root.
         * Otherwise, there is no reasonable way to validate that a suitable
         * protection is in place, since uid separation is the most obvious
         * protection.
         */
        if (getenv("DBUS_BROKER_TEST_DAEMON"))
                return 77;
        if (geteuid() != 0)
                return 77;

        test_fd_spam();

        return 0;
}
