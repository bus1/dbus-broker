#pragma once

/*
 * Audit Helpers
 */

#include <c-stdaux.h>
#include <stdlib.h>

enum {
        _UTIL_AUDIT_E_SUCCESS,

        UTIL_AUDIT_E_UNAVAILABLE,
};

enum {
        UTIL_AUDIT_TYPE_AVC,
        UTIL_AUDIT_TYPE_POLICYLOAD,
        UTIL_AUDIT_TYPE_MAC_STATUS,
};

int util_audit_drop_permissions(uint32_t uid, uint32_t gid);
int util_audit_log(int type, const char *message, uid_t uid);

int util_audit_init_global(void);
void util_audit_deinit_global(void);
