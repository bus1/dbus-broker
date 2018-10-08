#pragma once

/*
 * String Helpers
 */

#include <c-macro.h>
#include <stdlib.h>

enum {
        _UTIL_STRING_E_SUCCESS,

        UTIL_STRING_E_INVALID,
        UTIL_STRING_E_RANGE,
};

int util_strtou32(uint32_t *valp, const char *string);
int util_strtou64(uint64_t *valp, const char *string);
