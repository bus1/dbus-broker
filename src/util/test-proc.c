/*
 * Test Proc Utilities
 */

#undef NDEBUG
#include <c-stdaux.h>
#include <stdlib.h>
#include "util/proc.h"
#include "util/string.h"

static void test_field(void) {
        char *value;
        int r;

        r = proc_field(
                "key: value",
                "key",
                &value
        );
        c_assert(!r);
        c_assert(string_equal(value, "value"));
        c_free(value);

        r = proc_field(
                "key:",
                "key",
                &value
        );
        c_assert(!r);
        c_assert(string_equal(value, ""));
        c_free(value);

        r = proc_field(
                "key1: none\n \t \nkey\t \t: \t value\t \t\nkey2: none",
                "key",
                &value
        );
        c_assert(!r);
        c_assert(string_equal(value, "value"));
        c_free(value);

        r = proc_field("key: value", "key0", &value);
        c_assert(r == PROC_E_NOT_FOUND);
        r = proc_field("key0: value", "key", &value);
        c_assert(r == PROC_E_NOT_FOUND);
        r = proc_field(" key: value", "key", &value);
        c_assert(r == PROC_E_NOT_FOUND);
        r = proc_field("key key: value", "key", &value);
        c_assert(r == PROC_E_NOT_FOUND);
        r = proc_field("key", "key", &value);
        c_assert(r == PROC_E_NOT_FOUND);
}

int main(int argc, char **argv) {
        test_field();
        return 0;
}
