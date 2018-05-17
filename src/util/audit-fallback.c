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
#include <grp.h>
#include <stdlib.h>
#include <unistd.h>
#include "util/audit.h"
#include "util/error.h"
#include "util/misc.h"

/* see src/util/audit.c for details */
int util_audit_drop_permissions(uint32_t uid, uint32_t gid) {
        return util_drop_permissions(uid, gid);
}

int util_audit_log(const char *message, uid_t uid) {
        int r;

        r = fputs(message, stderr);
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
