/*
 * Audit Helpers
 */

#include <c-macro.h>
#include <libaudit.h>
#include <stdlib.h>
#include "util/audit.h"
#include "util/error.h"

static int audit_fd = -1;

/**
 * util_audit_log() - log a message to the audit subsystem
 * @message:    the message to be logged
 * @uid:        the UID of the user causing the message to be logged
 *
 * Log the message to the audit subsystem. If audit is disabled, log to
 * stderr instead.
 *
 * Return: 0 on success, or a negative error code on failure.
 */
int util_audit_log(const char *message, uid_t uid) {
        int r;

        if (audit_fd >= 0) {
                r = audit_log_user_avc_message(audit_fd, AUDIT_USER_AVC, message, NULL, NULL, NULL, uid);
                if (r <= 0)
                        return error_origin(-errno);
        } else {
                r = fputs(message, stderr);
                if (r < 0)
                        return error_origin(r);
        }

        return 0;
}

/**
 * util_audit_init_global() - initialize the global audit context
 *
 * Initialize the global audit context. This must be called before any
 * other audit function.
 *
 * Return: the 0 on success, negative error code on failure.
 */
int util_audit_init_global(void) {
        assert(audit_fd < 0);

        audit_fd = audit_open();

        return 0;
}

/**
 * util_audit_deinit_global() - deinitialize the global audit context
 *
 * Deinitialize the resources initialized by util_audit_init_global(). This
 * must be called exactly once, after which no more audit functions may be
 * called.
 */
void util_audit_deinit_global(void) {
        if (audit_fd < 0)
                return;

        audit_close(audit_fd);
        audit_fd = -1;
}
