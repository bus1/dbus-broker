/*
 * Test AppArmor Handling
 */

#undef NDEBUG
#include <c-stdaux.h>
#include <stdlib.h>
#include "util/apparmor.h"

static void test_basic(void) {
        bool enabled;
        int r;

        r = bus_apparmor_is_enabled(&enabled);
        c_assert(!r);
}

int main(int argc, char **argv) {
        test_basic();
        return 0;
}
