/*
 * Test Directory Watch
 */

#undef NDEBUG
#include <c-stdaux.h>
#include <stdlib.h>
#include "util/dirwatch.h"

static void test_basic(void) {
        int r, fd;

        /* test cleanup helper */
        {
                _c_cleanup_(dirwatch_freep) Dirwatch *dw1 = NULL, *dw2 = NULL;

                /* prevent 'unused variable' warning */
                dw1 = NULL;

                r = dirwatch_new(&dw2);
                assert(!r);
        }

        /* test no-op dispatcher */
        {
                _c_cleanup_(dirwatch_freep) Dirwatch *dw = NULL;

                r = dirwatch_new(&dw);
                assert(!r);

                fd = dirwatch_get_fd(dw);
                assert(fd >= 0);

                r = dirwatch_dispatch(dw);
                assert(!r);

                r = dirwatch_add(dw, ".");
                assert(!r);

                r = dirwatch_dispatch(dw);
                assert(!r);
        }
}

int main(int argc, char **argv) {
        test_basic();
        return 0;
}
