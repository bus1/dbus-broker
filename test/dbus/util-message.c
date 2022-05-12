/*
 * Raw message helpers
 */

#undef NDEBUG
#include <c-dvar.h>
#include <c-dvar-type.h>
#include <c-stdaux.h>
#include <stdlib.h>
#include "dbus/protocol.h"
#include "util-message.h"

#define TEST_T_MESSAGE(_body) \
        C_DVAR_T_TUPLE2(                                \
                C_DVAR_T_TUPLE7(                        \
                        C_DVAR_T_y,                     \
                        C_DVAR_T_y,                     \
                        C_DVAR_T_y,                     \
                        C_DVAR_T_y,                     \
                        C_DVAR_T_u,                     \
                        C_DVAR_T_u,                     \
                        C_DVAR_T_ARRAY(                 \
                                C_DVAR_T_TUPLE2(        \
                                        C_DVAR_T_y,     \
                                        C_DVAR_T_v      \
                                )                       \
                        )                               \
                ),                                      \
                _body                                   \
        )

static const CDVarType test_type_empty[] = {
        C_DVAR_T_INIT(
                TEST_T_MESSAGE(
                        C_DVAR_T_TUPLE0
                )
        )
};

static void test_message_append(void **buf, size_t *n_buf, const void *data, size_t n_data) {
        char *p;

        p = realloc(*buf, *n_buf + n_data);
        c_assert(p);

        c_memcpy(p + *n_buf, data, n_data);

        *buf = p;
        *n_buf += n_data;
}

void test_message_append_sasl(void **buf, size_t *n_buf) {
        const char *sasl = "\0AUTH EXTERNAL\r\nDATA\r\nNEGOTIATE_UNIX_FD\r\nBEGIN\r\n";
        size_t n_sasl = 1 + strlen(sasl + 1);

        test_message_append(buf, n_buf, sasl, n_sasl);
}

static void test_cdvar_message_header(CDVar *var,
                                      uint8_t type,
                                      uint32_t serial,
                                      uint32_t reply_serial,
                                      const char *sender,
                                      const char *destination,
                                      const char *path,
                                      const char *interface,
                                      const char *member) {
        c_assert(serial);

        c_dvar_write(var, "((yyyyuu[",
                     c_dvar_is_big_endian(var) ? 'B' : 'l', type, 0, 1, 0, serial);

        if (reply_serial)
                c_dvar_write(var, "(y<u>)",
                             DBUS_MESSAGE_FIELD_REPLY_SERIAL, c_dvar_type_u, reply_serial);

        if (sender)
                c_dvar_write(var, "(y<s>)",
                             DBUS_MESSAGE_FIELD_SENDER, c_dvar_type_s, sender);

        if (destination)
                c_dvar_write(var, "(y<s>)",
                             DBUS_MESSAGE_FIELD_DESTINATION, c_dvar_type_s, destination);

        if (path)
                c_dvar_write(var, "(y<o>)",
                             DBUS_MESSAGE_FIELD_PATH, c_dvar_type_o, path);

        if (interface)
                c_dvar_write(var, "(y<s>)",
                             DBUS_MESSAGE_FIELD_INTERFACE, c_dvar_type_s, interface);

        if (member)
                c_dvar_write(var, "(y<s>)",
                             DBUS_MESSAGE_FIELD_MEMBER, c_dvar_type_s, member);

        c_dvar_write(var, "])())");
}

void test_message_append_hello(void **buf, size_t *n_buf) {
        CDVar var = C_DVAR_INIT;
        void *hello;
        size_t n_hello;
        int r;

        c_dvar_begin_write(&var, (__BYTE_ORDER == __BIG_ENDIAN), test_type_empty, 1);

        test_cdvar_message_header(&var,
                                  DBUS_MESSAGE_TYPE_METHOD_CALL,
                                  1,
                                  0,
                                  NULL,
                                  "org.freedesktop.DBus",
                                  "/org/freedesktop/DBus",
                                  "org.freedesktop.DBus",
                                  "Hello");

        r = c_dvar_end_write(&var, &hello, &n_hello);
        c_assert(!r);

        test_message_append(buf, n_buf, hello, n_hello);

        free(hello);
        c_dvar_deinit(&var);
}

void test_message_append_broadcast(void **buf,
                                   size_t *n_buf,
                                   uint64_t sender_id) {
        CDVar var = C_DVAR_INIT;
        void *broadcast;
        size_t n_broadcast;
        char *sender;
        int r;

        r = asprintf(&sender, ":1.%"PRIu64, sender_id);
        c_assert(r >= 0);

        c_dvar_begin_write(&var, (__BYTE_ORDER == __BIG_ENDIAN), test_type_empty, 1);

        test_cdvar_message_header(&var,
                                  DBUS_MESSAGE_TYPE_METHOD_CALL,
                                  -1,
                                  0,
                                  sender,
                                  NULL,
                                  "/org/example/Foo",
                                  "org.example.Bar",
                                  "Baz");

        r = c_dvar_end_write(&var, &broadcast, &n_broadcast);
        c_assert(!r);

        test_message_append(buf, n_buf, broadcast, n_broadcast);

        free(sender);
        free(broadcast);
        c_dvar_deinit(&var);
}

void test_message_append_ping2(void **buf,
                              size_t *n_buf,
                              uint32_t serial,
                              const char *sender,
                              const char *destination) {
        CDVar var = C_DVAR_INIT;
        void *ping;
        size_t n_ping;
        int r;

        c_dvar_begin_write(&var, (__BYTE_ORDER == __BIG_ENDIAN), test_type_empty, 1);

        test_cdvar_message_header(&var,
                                  DBUS_MESSAGE_TYPE_METHOD_CALL,
                                  serial,
                                  0,
                                  sender,
                                  destination,
                                  "/org/freedesktop/DBus",
                                  "org.freedesktop.DBus.Peer",
                                  "Ping");

        r = c_dvar_end_write(&var, &ping, &n_ping);
        c_assert(!r);

        test_message_append(buf, n_buf, ping, n_ping);

        free(ping);
        c_dvar_deinit(&var);
}

void test_message_append_ping(void **buf,
                              size_t *n_buf,
                              uint32_t serial,
                              uint64_t sender_id,
                              uint64_t destination_id) {
        char *sender;
        char *destination;
        int r;

        r = asprintf(&sender, ":1.%"PRIu64, sender_id);
        c_assert(r >= 0);

        r = asprintf(&destination, ":1.%"PRIu64, destination_id);
        c_assert(r >= 0);

        test_message_append_ping2(buf, n_buf, serial, sender, destination);

        free(destination);
        free(sender);
}

void test_message_append_pong(void **buf,
                              size_t *n_buf,
                              uint32_t serial,
                              uint32_t reply_serial,
                              uint64_t sender_id,
                              uint64_t destination_id) {
        CDVar var = C_DVAR_INIT;
        void *pong;
        size_t n_pong;
        char *sender;
        char *destination;
        int r;

        r = asprintf(&sender, ":1.%"PRIu64, sender_id);
        c_assert(r >= 0);

        r = asprintf(&destination, ":1.%"PRIu64, destination_id);
        c_assert(r >= 0);

        c_dvar_begin_write(&var, (__BYTE_ORDER == __BIG_ENDIAN), test_type_empty, 1);

        test_cdvar_message_header(&var,
                                  DBUS_MESSAGE_TYPE_METHOD_RETURN,
                                  serial,
                                  reply_serial,
                                  sender,
                                  destination,
                                  NULL,
                                  NULL,
                                  NULL);

        r = c_dvar_end_write(&var, &pong, &n_pong);
        c_assert(!r);

        test_message_append(buf, n_buf, pong, n_pong);

        free(destination);
        free(sender);
        free(pong);
        c_dvar_deinit(&var);
}

void test_message_append_signal(void **buf,
                                size_t *n_buf,
                                uint64_t sender_id,
                                uint64_t destination_id) {
        CDVar var = C_DVAR_INIT;
        void *signal;
        size_t n_signal;
        char *sender;
        char *destination;
        int r;

        r = asprintf(&sender, ":1.%"PRIu64, sender_id);
        c_assert(r >= 0);

        r = asprintf(&destination, ":1.%"PRIu64, destination_id);
        c_assert(r >= 0);

        c_dvar_begin_write(&var, (__BYTE_ORDER == __BIG_ENDIAN), test_type_empty, 1);

        test_cdvar_message_header(&var,
                                  DBUS_MESSAGE_TYPE_SIGNAL,
                                  -1,
                                  0,
                                  sender,
                                  destination,
                                  "/org/example/Foo",
                                  "org.examelp.Bar",
                                  "Baz");

        r = c_dvar_end_write(&var, &signal, &n_signal);
        c_assert(!r);

        test_message_append(buf, n_buf, signal, n_signal);

        free(destination);
        free(sender);
        free(signal);
        c_dvar_deinit(&var);
}
