/*
 * Test D-Bus Message Sender Stitching
 */

#undef NDEBUG
#include <c-dvar.h>
#include <c-dvar-type.h>
#include <c-stdaux.h>
#include <stdlib.h>
#include "dbus/address.h"
#include "dbus/message.h"
#include "dbus/protocol.h"

static const CDVarType test_message_type[] = {
        C_DVAR_T_INIT(
                /* ((yyyyuua(yv))(uuu)) */
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
                        C_DVAR_T_TUPLE3(
                                C_DVAR_T_u,
                                C_DVAR_T_u,
                                C_DVAR_T_u
                        )
                )
        )
};

static Message *test_new_message(size_t before, const char *sender_early, size_t after, const char *sender_late) {
        _c_cleanup_(c_dvar_deinit) CDVar v = C_DVAR_INIT;
        Message *message;
        size_t n_data;
        void *data;
        char *p;
        int r;

        c_dvar_begin_write(&v, (__BYTE_ORDER == __BIG_ENDIAN), test_message_type, 1);
        c_dvar_write(&v, "((yyyyuu[",
                     c_dvar_is_big_endian(&v) ? 'B' : 'l',
                     128,
                     1,
                     1,
                     0,
                     (uint32_t)-1);
        c_dvar_write(&v, "(y<g>)",
                     DBUS_MESSAGE_FIELD_SIGNATURE,
                     &c_dvar_type_g,
                     "uuu");

        if (before) {
                p = malloc(before + 1);
                c_assert(p);
                c_memset(p, 'a', before);
                p[before] = 0;

                c_dvar_write(&v, "(y<s>)",
                             DBUS_MESSAGE_FIELD_MEMBER,
                             &c_dvar_type_s,
                             p);
                free(p);
        }

        if (sender_early) {
                c_dvar_write(&v, "(y<s>)",
                             DBUS_MESSAGE_FIELD_SENDER,
                             &c_dvar_type_s,
                             sender_early);
        }

        if (after) {
                p = malloc(after + 1);
                c_assert(p);
                c_memset(p, 'a', after);
                p[0] = '/';
                p[after] = 0;

                c_dvar_write(&v, "(y<o>)",
                             DBUS_MESSAGE_FIELD_PATH,
                             &c_dvar_type_o,
                             p);

                free(p);
        }

        if (sender_late)
                c_dvar_write(&v, "(y<s>)",
                             DBUS_MESSAGE_FIELD_SENDER,
                             &c_dvar_type_s,
                             sender_late);

        c_dvar_write(&v, "])(uuu))", 7, 8, 9);
        r = c_dvar_end_write(&v, &data, &n_data);
        c_assert(!r);

        r = message_new_outgoing(&message, data, n_data);
        c_assert(!r);

        r = message_parse_metadata(message);
        c_assert(!r);

        return message;
}

static void test_assert_message(Message *message, size_t before, const char *sender, size_t after) {
        _c_cleanup_(message_unrefp) Message *expected = NULL;
        _c_cleanup_(c_freep) void *p = NULL;
        size_t i, n;

        expected = test_new_message(before, NULL, after, sender);

        for (n = 0, i = 0; i < C_ARRAY_SIZE(message->vecs); ++i)
                n += message->vecs[i].iov_len;

        p = malloc(n);
        c_assert(p);

        for (n = 0, i = 0; i < C_ARRAY_SIZE(message->vecs); ++i) {
                c_memcpy(p + n, message->vecs[i].iov_base, message->vecs[i].iov_len);
                n += message->vecs[i].iov_len;
        }

        c_assert(n == expected->n_data);
        c_assert(!memcmp(p, expected->data, n));
}

static void test_stitching(void) {
        Message *message;
        Address addr;
        size_t i, n;
        char *from, *to;

        /*
         * To test sender stitching, we repeatedly create messages with
         * different header fields, stitch them, and compare them with what we
         * expect as result.
         *
         * The different modulo-calculations here are used to get varying
         * combinations of string-lengths, so their size and padding differs on
         * each run.
         */

        for (i = 0; i < 1024; ++i) {
                n = 8 + i % 8;
                from = malloc(n + 1);
                c_assert(from);
                c_memset(from, '1', n);
                from[0] = ':';
                from[1] = '1';
                from[2] = '.';
                from[n] = 0;

                n = 8 + i % 11;
                to = malloc(n + 1);
                c_assert(to);
                c_memset(to, '2', n);
                to[0] = ':';
                to[1] = '1';
                to[2] = '.';
                to[n] = 0;

                address_from_string(&addr, to);
                c_assert(addr.type == ADDRESS_TYPE_ID);

                message = test_new_message(i % 13, from, i / 17, NULL);
                message_stitch_sender(message, addr.id);
                test_assert_message(message, i % 13, to, i / 17);
                message_unref(message);

                free(to);
                free(from);
        }
}

int main(int argc, char **argv) {
        test_stitching();
        return 0;
}
