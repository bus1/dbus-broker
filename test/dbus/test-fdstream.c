/*
 * Verify FD streaming constraints
 */

#undef NDEBUG
#include <c-dvar.h>
#include <c-dvar-type.h>
#include <c-stdaux.h>
#include <stdlib.h>
#include "dbus/connection.h"
#include "dbus/message.h"
#include "dbus/protocol.h"
#include "util/dispatch.h"
#include "util/fdlist.h"
#include "util-broker.h"

enum {
        TEST_FD_STREAM_PIPELINE,
        TEST_FD_STREAM_SEQUENTIAL,
        TEST_FD_STREAM_SPLIT,
        _TEST_FD_STREAM_N,
};

static unsigned int test_fd_stream_mode;
static unsigned int test_fd_stream_seq;
static unsigned int test_fd_stream_got;

static void test_fd_stream_send(Connection *c, unsigned int unix_fds, unsigned int n_fds) {
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
        _c_cleanup_(message_unrefp) Message *m = NULL;
        size_t n_data;
        void *data;
        int r;

        c_dvar_begin_write(&v, (__BYTE_ORDER == __BIG_ENDIAN), type, 1);

        c_dvar_write(&v, "((yyyyuu[(y<s>)(y<o>)(y<s>)(y<u>)])())",
                     c_dvar_is_big_endian(&v) ? 'B' : 'l',
                     DBUS_MESSAGE_TYPE_METHOD_CALL,
                     DBUS_HEADER_FLAG_NO_REPLY_EXPECTED,
                     1, 0, ++test_fd_stream_seq,
                     DBUS_MESSAGE_FIELD_DESTINATION, c_dvar_type_s, ":1.0",
                     DBUS_MESSAGE_FIELD_PATH, c_dvar_type_o, "/",
                     DBUS_MESSAGE_FIELD_MEMBER, c_dvar_type_s, "Foobar",
                     DBUS_MESSAGE_FIELD_UNIX_FDS, c_dvar_type_u, unix_fds);

        r = c_dvar_end_write(&v, &data, &n_data);
        c_assert(!r);

        r = message_new_outgoing(&m, data, n_data);
        c_assert(!r);

        if (n_fds > 0) {
                int fds[n_fds];

                c_memset(fds, 0, sizeof(fds));
                r = fdlist_new_with_fds(&m->fds, fds, n_fds);
                c_assert(!r);
        }

        r = connection_queue(c, NULL, m);
        c_assert(!r);
}

static void test_fd_stream_hello(Connection *c) {
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
        _c_cleanup_(message_unrefp) Message *m = NULL;
        size_t n_data;
        void *data;
        int r;

        c_dvar_begin_write(&v, (__BYTE_ORDER == __BIG_ENDIAN), type, 1);

        c_dvar_write(&v, "((yyyyuu[(y<s>)(y<o>)(y<s>)])())",
                     c_dvar_is_big_endian(&v) ? 'B' : 'l',
                     DBUS_MESSAGE_TYPE_METHOD_CALL,
                     0, 1, 0, ++test_fd_stream_seq,
                     DBUS_MESSAGE_FIELD_DESTINATION, c_dvar_type_s, "org.freedesktop.DBus",
                     DBUS_MESSAGE_FIELD_PATH, c_dvar_type_o, "/org/freedesktop/DBus",
                     DBUS_MESSAGE_FIELD_MEMBER, c_dvar_type_s, "Hello");

        r = c_dvar_end_write(&v, &data, &n_data);
        c_assert(!r);

        r = message_new_outgoing(&m, data, n_data);
        c_assert(!r);

        r = connection_queue(c, NULL, m);
        c_assert(!r);
}

static int test_fd_stream_fn(DispatchFile *file) {
        Connection *c = c_container_of(file, Connection, socket_file);
        int r;

        r = connection_dispatch(c, dispatch_file_events(file));
        c_assert(!r);

        do {
                _c_cleanup_(message_unrefp) Message *m = NULL;

                r = connection_dequeue(c, &m);
                if (!r) {
                        if (!m)
                                break;

                        r = message_parse_metadata(m);
                        c_assert(!r);
                        c_assert(m->metadata.fields.unix_fds == fdlist_count(m->fds));

                        if (m->metadata.fields.reply_serial == 1) {

                                c_assert(!strcmp(m->metadata.args[0].value, ":1.0"));
                                c_assert(!m->metadata.fields.unix_fds);
                                ++test_fd_stream_got;

                                if (test_fd_stream_mode == TEST_FD_STREAM_SEQUENTIAL)
                                        test_fd_stream_send(c, 0, 0);
                                else if (test_fd_stream_mode == TEST_FD_STREAM_SPLIT)
                                        test_fd_stream_send(c, 0, 1);

                        } else if (m->metadata.header.type == DBUS_MESSAGE_TYPE_METHOD_CALL &&
                                   m->metadata.header.serial == 2) {

                                c_assert(!m->metadata.fields.unix_fds);
                                ++test_fd_stream_got;

                                if (test_fd_stream_mode == TEST_FD_STREAM_SEQUENTIAL)
                                        test_fd_stream_send(c, 1, 1);
                                else if (test_fd_stream_mode == TEST_FD_STREAM_SPLIT)
                                        test_fd_stream_send(c, 1, 0);

                        } else if (m->metadata.header.type == DBUS_MESSAGE_TYPE_METHOD_CALL &&
                                   m->metadata.header.serial == 3) {

                                c_assert(test_fd_stream_mode != TEST_FD_STREAM_SPLIT);
                                c_assert(m->metadata.fields.unix_fds == 1);
                                ++test_fd_stream_got;

                                connection_shutdown(c);

                        } else {
                                c_assert(m->metadata.header.type == DBUS_MESSAGE_TYPE_SIGNAL);
                        }
                }
        } while (!r);

        if (r == CONNECTION_E_EOF) {
                connection_shutdown(c);
                return connection_is_running(c) ? 0 : DISPATCH_E_EXIT;
        }

        c_assert(!r);
        return 0;
}

static void test_fd_stream(void) {
        _c_cleanup_(c_closep) int fd = -1;
        _c_cleanup_(dispatch_context_deinit) DispatchContext d = DISPATCH_CONTEXT_NULL(d);
        _c_cleanup_(connection_deinit) Connection c = CONNECTION_NULL(c);
        _c_cleanup_(util_broker_freep) Broker *broker = NULL;
        int r;

        /*
         * This test connects a single client to the broker, performs a SASL
         * and Hello() handshake and then sends two method-calls to itself. Of
         * those two method-calls, the first carries no FD, the second one
         * carries a single FD.
         *
         * This test can be run in several different variants:
         *
         *   1) SASL+Hello()+Methods are all pipelined, thus verifying that we
         *      correctly dispatch messages regardless how they're batched.
         *
         *   2) SASL+Hello() are pipelined, followed by unpipelined Methods.
         *      This is used to verify the behavior is the same as with
         *      pipelineing.
         *
         *   3) The two Methods are invoked with UNIX_FDS=0, followed by
         *      UNIX_FDS=1, but only the first Method carries an actual FD.
         *      This must be rejected by the broker, since FDs are always
         *      attached to the buffers they were sent with and do *NOT* form a
         *      separate stream.
         */

        util_broker_new(&broker);
        util_broker_spawn(broker);

        /* setup client connection */
        {
                r = dispatch_context_init(&d);
                c_assert(!r);

                util_broker_connect_fd(broker, &fd);

                r = connection_init_client(&c, &d, test_fd_stream_fn, NULL, fd);
                c_assert(!r);

                r = connection_open(&c);
                c_assert(!r);
        }

        /* send initial messages */
        {
                test_fd_stream_hello(&c);
                if (test_fd_stream_mode == TEST_FD_STREAM_PIPELINE) {
                        test_fd_stream_send(&c, 0, 0);
                        test_fd_stream_send(&c, 1, 1);
                }
        }

        /* dispatch event loop */
        {
                do {
                        r = dispatch_context_dispatch(&d);
                        c_assert(!r || r == DISPATCH_E_EXIT);
                } while (!r);
        }

        util_broker_terminate(broker);
}

int main(int argc, char **argv) {
        /*
         * dbus-daemon(1) fails this test, so skip it if run under it. Note
         * that dbus-daemon(1) treats auxiliary FDs as a secondary out-of-band
         * stream, thus incorrectly matching them to messages. Furthermore,
         * dbus-daemon(1) cannot pipeline SASL and following D-Bus messages, if
         * they carry FDs.
         *
         * At the time of writing, neither of those issues were fixed in
         * dbus-daemon(1), so we disable the test. Both issues are reported and
         * are hopefully fixed soon. See BZ #101754, #101755
         */
        if (util_is_reference())
                return 77;

        for (unsigned int i = 0; i < _TEST_FD_STREAM_N; ++i) {
                test_fd_stream_mode = i;
                test_fd_stream_seq = 0;
                test_fd_stream_got = 0;

                test_fd_stream();

                c_assert(test_fd_stream_mode == i);
                c_assert(test_fd_stream_seq == 3);

                if (test_fd_stream_mode == TEST_FD_STREAM_SPLIT)
                        c_assert(test_fd_stream_got == 2);
                else
                        c_assert(test_fd_stream_got == 3);
        }

        return 0;
}
