/*
 * Audit Helpers
 *
 * This fallback is used when libaudit is not available, and is meant to be
 * functionally equivalent to util/audit.c in case audit is disabled at
 * runtime, but without requiring the library.
 *
 * See util/audit.c for details.
 */

#include <c-macro.h>
#include <stdlib.h>
#include "util/audit.h"
#include "util/error.h"

int util_audit_log(const char *message, uid_t uid) {
        int r;

        r = fprintf(stderr, message);
        if (r < 0)
                return error_origin(r);

        return 0;
}

int util_audit_init_global(void) {
        return 0;
}

void util_audit_deinit_global(void) {
        return;
}
