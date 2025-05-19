/*
 * Audit Helpers
 */

#include <c-stdaux.h>
#include <cap-ng.h>
#include <grp.h>
#include <libaudit.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <unistd.h>
#include "util/audit.h"
#include "util/error.h"

static int audit_fd = -1;

/**
 * util_audit_drop_permissions() - drop process permissions
 * @uid:        uid to set
 * @gid:        gid to set
 *
 * This performs a setuid(2) and setgid(2) syscall, clearing all process
 * permissions we have, but retaining required capabilities.
 *
 * The reason this lives in the audit-subsystem, is that the audit-subsystem is
 * the only code that needs to retain capabilities. Hence, the cap-ng
 * dependency is only required for the audit code. If the capability
 * dependencies get more comples, we have to rework this, but for now it should
 * be fine.
 *
 * Return: 0 on success, or a negative error code on failure.
 */
int util_audit_drop_permissions(uint32_t uid, uint32_t gid) {
        int r;

        /*
         * This is modeled exactly after the behavior of dbus-daemon(1). We
         * have to be compatibile and fail in the exact same situations. This
         * means, only try to retain CAP_AUDIT_WRITE if we are running as root
         * and own it. In all other cases, simply drop privileges to the
         * requested IDs.
         */

        if (geteuid() != 0) {
                /*
                 * For compatibility to dbus-daemon, this must be
                 * non-fatal.
                 */
                setgroups(0, NULL);

                r = setgid(gid);
                if (r < 0)
                        return error_origin(-errno);

                r = setuid(uid);
                if (r < 0)
                        return error_origin(-errno);
        } else {
                bool have_audit_write;

                r = capng_have_capability(CAPNG_PERMITTED, CAP_AUDIT_WRITE);
                if (r == CAPNG_FAIL)
                        return error_origin(-EIO);
                else if (r == 1)
                        have_audit_write = true;
                else
                        have_audit_write = false;

                capng_clear(CAPNG_SELECT_BOTH);

                if (have_audit_write) {
                        r = capng_update(CAPNG_ADD,
                                         CAPNG_EFFECTIVE | CAPNG_PERMITTED | CAPNG_INHERITABLE,
                                         CAP_AUDIT_WRITE);
                        if (r < 0)
                                return error_origin(-EINVAL);
                }

                r = capng_change_id(uid, gid, CAPNG_DROP_SUPP_GRP);
                if (r)
                        return error_origin(-EPERM);

                if (have_audit_write) {
                        r = prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, CAP_AUDIT_WRITE, 0, 0);
                        if (r < 0)
                                return error_origin(-errno);
                }
        }

        return 0;
}

/**
 * util_audit_log() - log a message to the audit subsystem
 * @type:       the audit message type, see enum in audit.h
 * @message:    the message to be logged
 * @uid:        the UID of the user causing the message to be logged
 *
 * Log the message to the audit subsystem. If audit is disabled, return
 * UTIL_AUDIT_E_UNAVAILABLE instead.
 *
 * Return: 0 on success, UTIL_AUDIT_E_UNAVAILABLE if audit is not
 *         available, or a negative error code on failure.
 */
int util_audit_log(int type, const char *message, uid_t uid) {
        int r;

        if (audit_fd < 0)
                return UTIL_AUDIT_E_UNAVAILABLE;

        switch (type) {
        case UTIL_AUDIT_TYPE_AVC:
                r = audit_log_user_avc_message(
                        audit_fd,
                        AUDIT_USER_AVC,
                        message,
                        NULL,
                        NULL,
                        NULL,
                        uid
                );
                break;
        case UTIL_AUDIT_TYPE_POLICYLOAD:
                r = audit_log_user_message(
                        audit_fd,
                        AUDIT_USER_MAC_POLICY_LOAD,
                        message,
                        NULL,
                        NULL,
                        NULL,
                        1
                );
                break;
        case UTIL_AUDIT_TYPE_MAC_STATUS:
                r = audit_log_user_message(
                        audit_fd,
                        AUDIT_USER_MAC_STATUS,
                        message,
                        NULL,
                        NULL,
                        NULL,
                        1
                );
                break;
        default:
                return error_origin(-ENOTRECOVERABLE);
        }

        if (r <= 0)
                return error_origin(-errno);

        return 0;
}

/**
 * util_audit_init_global() - initialize the global audit context
 *
 * Initialize the global audit context. This must be called before any
 * other audit function. If audit is not supported, the context is
 * initialized to indicate that, but the function still succeeds.
 *
 * Return: the 0 on success, negative error code on failure.
 */
int util_audit_init_global(void) {
        int r;

        c_assert(audit_fd < 0);

        r = capng_have_capability(CAPNG_EFFECTIVE, CAP_AUDIT_WRITE);
        if (r == 0)
                /*
                 * Without the right capability, any writes will fail, so treat this
                 * as if audit is unsupported.
                 */
                return 0;
        else if (r == CAPNG_FAIL)
                return error_origin(-EIO);

        r = audit_open();
        if (r < 0 && errno != EINVAL && errno != EPROTONOSUPPORT && errno != EAFNOSUPPORT)
                return error_origin(-errno);

        audit_fd = r;

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
