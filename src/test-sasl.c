/*
 * Test SASL Parser
 */

#include <c-macro.h>
#include <stdlib.h>
#include "dbus-sasl.h"

static void test_setup(void) {
        DBusSASL sasl;

        dbus_sasl_init(&sasl, 1, "123456789abcdef");
        dbus_sasl_deinit(&sasl);
}

static void assert_dispatch(DBusSASL *sasl, char *in, char *out, int ret) {
        char buffer[DBUS_SASL_MAX_OUT_LINE_LENGTH];
        size_t n_buffer;
        int r;

        assert(strlen(out) <= DBUS_SASL_MAX_OUT_LINE_LENGTH);

        r = dbus_sasl_dispatch(sasl, in, buffer, &n_buffer);
        assert(r == ret);
        if (r == 0) {
                assert(n_buffer == strlen(out));
                assert(strncmp(buffer, out, n_buffer) == 0);
        }
}

/* discover the available mechanisms */
static void test_discover(void) {
        DBusSASL sasl;

        dbus_sasl_init(&sasl, 1, "0123456789abcdef");

        assert_dispatch(&sasl, "AUTH", "REJECTED EXTERNAL ANONYMOUS\r\n", 0);

        dbus_sasl_deinit(&sasl);
}

/* use anonymous authentication */
static void test_anonymous(void) {
        DBusSASL sasl;

        dbus_sasl_init(&sasl, 1, "0123456789abcdef");

        assert_dispatch(&sasl, "AUTH ANONYMOUS trace",
                       "OK 30313233343536373839616263646566\r\n", 0);
        assert_dispatch(&sasl, "BEGIN", "", 1);

        dbus_sasl_deinit(&sasl);
}

/* anonymous and negotiate fds */
static void test_anonymous_fds(void) {
        DBusSASL sasl;

        dbus_sasl_init(&sasl, 1, "0123456789abcdef");

        assert_dispatch(&sasl, "AUTH ANONYMOUS trace",
                       "OK 30313233343536373839616263646566\r\n", 0);
        assert_dispatch(&sasl, "NEGOTIATE_UNIX_FD", "AGREE_UNIX_FD\r\n", 0);
        assert_dispatch(&sasl, "BEGIN", "", 1);

        dbus_sasl_deinit(&sasl);
}

/* use anonymous without providing a trace, this requires another roundtrip */
static void test_anonymous_no_data(void) {
        DBusSASL sasl;

        dbus_sasl_init(&sasl, 1, "0123456789abcdef");

        assert_dispatch(&sasl, "AUTH ANONYMOUS", "DATA\r\n", 0);
        assert_dispatch(&sasl, "DATA",
                                "OK 30313233343536373839616263646566\r\n", 0);
        assert_dispatch(&sasl, "BEGIN", "", 1);

        dbus_sasl_deinit(&sasl);
}

/* test external */
static void test_external(void) {
        DBusSASL sasl;

        dbus_sasl_init(&sasl, 1, "0123456789abcdef");

        assert_dispatch(&sasl, "AUTH EXTERNAL 31",
                       "OK 30313233343536373839616263646566\r\n", 0);
        assert_dispatch(&sasl, "BEGIN", "", 1);

        dbus_sasl_deinit(&sasl);
}

/* verify that authentiacitng with the wrong uid fails, but retrying succeeds */
static void test_external_invalid(void) {
        DBusSASL sasl;

        dbus_sasl_init(&sasl, 1, "0123456789abcdef");

        assert_dispatch(&sasl, "AUTH EXTERNAL 30",
                                        "REJECTED EXTERNAL ANONYMOUS\r\n", 0);
        assert_dispatch(&sasl, "AUTH EXTERNAL 31",
                       "OK 30313233343536373839616263646566\r\n", 0);
        assert_dispatch(&sasl, "BEGIN", "", 1);

        dbus_sasl_deinit(&sasl);
}

/* do not supply a uid, but allow the system to use the one it has */
static void test_external_no_data(void) {
        DBusSASL sasl;

        dbus_sasl_init(&sasl, 1, "0123456789abcdef");

        assert_dispatch(&sasl, "AUTH EXTERNAL", "DATA\r\n", 0);
        assert_dispatch(&sasl, "DATA",
                                "OK 30313233343536373839616263646566\r\n", 0);
        assert_dispatch(&sasl, "BEGIN", "", 1);

        dbus_sasl_deinit(&sasl);
}

/* external and negotiate fds, this is the common case */
static void test_external_fds(void) {
        DBusSASL sasl;

        dbus_sasl_init(&sasl, 1, "0123456789abcdef");

        assert_dispatch(&sasl, "AUTH EXTERNAL 31",
                       "OK 30313233343536373839616263646566\r\n", 0);
        assert_dispatch(&sasl, "NEGOTIATE_UNIX_FD", "AGREE_UNIX_FD\r\n", 0);
        assert_dispatch(&sasl, "BEGIN", "", 1);

        dbus_sasl_deinit(&sasl);
}

int main(int argc, char **argv) {
        test_setup();
        test_discover();
        test_anonymous();
        test_anonymous_fds();
        test_anonymous_no_data();
        test_external();
        test_external_invalid();
        test_external_no_data();
        test_external_fds();
        return 0;
}
