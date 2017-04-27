#pragma once

/*
 * Unique Name
 */

#include <c-macro.h>
#include <stdint.h>
#include <stdlib.h>

enum {
        _UNIQUE_NAME_E_SUCCESS,

        UNIQUE_NAME_E_CORRUPT,
        UNIQUE_NAME_E_RANGE,
};

#define UNIQUE_NAME_ID_INVALID (ULLONG_MAX)
#define UNIQUE_NAME_STRING_MAX (3 + C_DECIMAL_MAX(uint64_t) + 1)

void unique_name_from_id(char *name, uint64_t id);
int unique_name_to_id(const char *name, uint64_t *idp);
