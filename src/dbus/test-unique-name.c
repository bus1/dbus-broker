/*
 * Test Unique Name Handling
 */

#include <stdlib.h>
#include "dbus/unique-name.h"

static void test_basic(void) {
        char name[UNIQUE_NAME_STRING_MAX];
        uint64_t id = UNIQUE_NAME_ID_INVALID;
        int r;

        unique_name_from_id(name, 0);
        assert(strcmp(name, ":1.0") == 0);

        unique_name_from_id(name, UNIQUE_NAME_ID_INVALID - 1);
        assert(strcmp(name, ":1.18446744073709551614") == 0);

        r = unique_name_to_id(":1.0", &id);
        assert(!r);
        assert(id == 0);

        /* in the range of strtoull(), but we forbid it */
        r = unique_name_to_id(":1.18446744073709551615", &id);
        assert(r == UNIQUE_NAME_E_RANGE);

        /* out of range of strtoull() */
        r = unique_name_to_id(":1.184467440737095516156", &id);
        assert(r == UNIQUE_NAME_E_RANGE);

        /* corrupt after the number exceeded the range of strtoull() */
        r = unique_name_to_id(":1.184467440737095516156x", &id);
        assert(r == UNIQUE_NAME_E_CORRUPT);

        r = unique_name_to_id("org.freedesktop.DBus", &id);
        assert(r == UNIQUE_NAME_E_CORRUPT);

        r = unique_name_to_id("", &id);
        assert(r == UNIQUE_NAME_E_CORRUPT);

        r = unique_name_to_id(":2.11", &id);
        assert(r == UNIQUE_NAME_E_CORRUPT);

        r = unique_name_to_id(":1.1x", &id);
        assert(r == UNIQUE_NAME_E_CORRUPT);
}

int main(int argc, char **argv) {
        test_basic();
        return 0;
}
