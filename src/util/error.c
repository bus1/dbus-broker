/*
 * Error Handling
 */

#include <c-macro.h>
#include <stdlib.h>
#include "util/error.h"

/**
 * error_slow_origin() - XXX
 */
int error_slow_origin(int r, const char *function, const char *file, int line) {
        assert(r);

        if (r < 0) {
                int err = errno;

                errno = -r;
                fprintf(stderr, "ERROR %s @ %s +%d: %m\n", function, file, line);
                errno = err;

                return r;
        }

        fprintf(stderr, "ERROR %s @ %s +%d: Return code %d\n", function, file, line, r);

        return -ENOTRECOVERABLE;
}

/**
 * error_slow_fold() - XXX
 */
int error_slow_fold(int r, const char *function, const char *file, int line) {
        assert(r < 0);

        fprintf(stderr, "      %s @ %s +%d\n", function, file, line);

        return r;
}
