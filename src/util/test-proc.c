/*
 * Test Proc Utilities
 */

#undef NDEBUG
#include <c-stdaux.h>
#include <stdlib.h>
#include "util/proc.h"
#include "util/string.h"
#include "util/syscall.h"

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

static void test_read(void) {
        _c_cleanup_(c_closep) int fd = -1;
        const char *str = "01234567";
        size_t i, n_data;
        char *data;
        ssize_t l;
        int r;

        fd = syscall_memfd_create("test-proc", 0x1);
        c_assert(fd >= 0);

        for (i = 0; i < 1024; i += strlen(str)) {
                l = pwrite(fd, str, strlen(str), i);
                c_assert(l == 8);
        }

        r = proc_read(fd, &data, &n_data);
        c_assert(!r);
        c_assert(n_data == 1024);
        c_free(data);

        for ( ; i < 8192; i += strlen(str)) {
                l = pwrite(fd, str, strlen(str), i);
                c_assert(l == 8);
        }

        r = proc_read(fd, &data, &n_data);
        c_assert(!r);
        c_assert(n_data == 8192);
        c_free(data);
}

int main(int argc, char **argv) {
        test_field();
        test_read();
        return 0;
}
