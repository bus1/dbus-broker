#pragma once

/*
 * Audit Helpers
 */

#include <c-macro.h>
#include <stdlib.h>

int util_audit_drop_permissions(uint32_t uid, uint32_t gid);
int util_audit_log(const char *message, uid_t uid);

int util_audit_init_global(void);
void util_audit_deinit_global(void);
