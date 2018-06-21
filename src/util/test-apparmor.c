/*
 * Test AppArmor Handling
 */

#include <c-macro.h>
#include <stdlib.h>
#include "util/apparmor.h"

static void test_basic(void) {
        bool enabled;
        int r;

        r = bus_apparmor_is_enabled(&enabled);
        assert(!r);
}

int main(int argc, char **argv) {
        test_basic();
        return 0;
}
