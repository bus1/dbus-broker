/*
 * Test nanosecond time management
 */

#undef NDEBUG
#include <c-stdaux.h>
#include <stdlib.h>
#include "util/nsec.h"

static void test_nsec(void) {
        nsec_t n0, n1, n2;

        n0 = nsec_now(CLOCK_MONOTONIC);
        c_assert(n0 > 0);

        n1 = n0 + 8000;
        nsec_sleep(CLOCK_MONOTONIC, n1);

        n2 = nsec_now(CLOCK_MONOTONIC);
        c_assert(n2 > 0);
        c_assert(n2 > n0);
        c_assert(n2 - n0 >= 8000);
}

int main(int argc, char **argv) {
        test_nsec();
        return 0;
}
