/*
 * Test SASL Parser
 */

#include <c-macro.h>
#include <stdlib.h>
#include "dbus/sasl.h"

static void test_setup(void) {
        SASLServer sasl;

        sasl_server_init(&sasl, 1, "123456789abcdef");
        sasl_server_deinit(&sasl);
}

static void assert_dispatch(SASLServer *sasl, const char *in, const char *out, int ret) {
        const char *reply = NULL;
        size_t n_reply = 0;
        int r;

        r = sasl_server_dispatch(sasl, in, strlen(in + 1) + 1, &reply, &n_reply);
        assert(r == ret);
        if (r == 0) {
                if (out) {
                        assert(n_reply == strlen(out));
                        assert(strcmp(reply, out) == 0);
                } else {
                        assert(!n_reply);
                        assert(!reply);
                        assert(sasl_server_is_done(sasl));
                }
        }
}

/* discover the available mechanisms */
static void test_discover(void) {
        SASLServer sasl;

        sasl_server_init(&sasl, 1, "0123456789abcdef");

        assert_dispatch(&sasl, "\0AUTH", "REJECTED EXTERNAL", 0);

        sasl_server_deinit(&sasl);
}

/* test external */
static void test_external(void) {
        SASLServer sasl;

        sasl_server_init(&sasl, 1, "0123456789abcdef");

        assert_dispatch(&sasl, "\0AUTH EXTERNAL 31", "OK 30313233343536373839616263646566", 0);
        assert_dispatch(&sasl, "BEGIN", NULL, 0);

        sasl_server_deinit(&sasl);
}

/* verify that authentiacitng with the wrong uid fails, but retrying succeeds */
static void test_external_invalid(void) {
        SASLServer sasl;

        sasl_server_init(&sasl, 1, "0123456789abcdef");

        assert_dispatch(&sasl, "\0AUTH EXTERNAL 30", "REJECTED EXTERNAL", 0);
        assert_dispatch(&sasl, "AUTH EXTERNAL 31", "OK 30313233343536373839616263646566", 0);
        assert_dispatch(&sasl, "BEGIN", NULL, 0);

        sasl_server_deinit(&sasl);
}

/* do not supply a uid, but allow the system to use the one it has */
static void test_external_no_data(void) {
        SASLServer sasl;

        sasl_server_init(&sasl, 1, "0123456789abcdef");

        assert_dispatch(&sasl, "\0AUTH EXTERNAL", "DATA", 0);
        assert_dispatch(&sasl, "DATA", "OK 30313233343536373839616263646566", 0);
        assert_dispatch(&sasl, "BEGIN", NULL, 0);

        sasl_server_deinit(&sasl);
}

/* external and negotiate fds, this is the common case */
static void test_external_fds(void) {
        SASLServer sasl;

        sasl_server_init(&sasl, 1, "0123456789abcdef");

        assert_dispatch(&sasl, "\0AUTH EXTERNAL 31", "OK 30313233343536373839616263646566", 0);
        assert_dispatch(&sasl, "NEGOTIATE_UNIX_FD", "AGREE_UNIX_FD", 0);
        assert_dispatch(&sasl, "BEGIN", NULL, 0);

        sasl_server_deinit(&sasl);
}

int main(int argc, char **argv) {
        test_setup();
        test_discover();
        test_external();
        test_external_invalid();
        test_external_no_data();
        test_external_fds();
        return 0;
}
