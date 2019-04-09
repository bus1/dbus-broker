#pragma once

/*
 * Miscellaneous Helpers
 */

#include <c-stdaux.h>
#include <stdlib.h>

uint64_t util_umul64_saturating(uint64_t a, uint64_t b);
int util_drop_permissions(uint32_t uid, uint32_t gid);
