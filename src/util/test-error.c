/*
 * Test Error Handling
 */

#undef NDEBUG
#include <c-stdaux.h>
#include <stdlib.h>
#include "util/error.h"

static void test_basic(void) {
        int r;

        /* error_origin(0) is a no-op */
        r = error_origin(0);
        c_assert(!r);

        /* make sure no double evaluation happens */
        r = error_origin(--r);
        c_assert(r == -1);

        /* error_origin() always returns <=0 */
        r = error_origin(1);
        c_assert(r < 0);

        /* error_trace(0) is a no-op */
        r = error_trace(0);
        c_assert(!r);

        /* make sure no double evaluation happens */
        r = error_trace(--r);
        c_assert(r == -1);

        /* error_trace() never modifies the error code */
        r = error_trace(1);
        c_assert(r == 1);

        /* error_fold(0) is a no-op */
        r = error_fold(0);
        c_assert(!r);

        /* make sure no double evaluation happens */
        r = error_fold(--r);
        c_assert(r == -1);

        /* error_fold() never returns positive codes */
        r = error_fold(1);
        c_assert(r < 0);
}

int main(int argc, char **argv) {
        test_basic();
        return 0;
}
