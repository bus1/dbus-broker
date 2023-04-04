/*
 * String Helpers
 */

#include <c-stdaux.h>
#include <stdlib.h>
#include <unistd.h>
#include "util/error.h"
#include "util/string.h"

int util_strtou32(uint32_t *valp, const char *string) {
        unsigned long val;
        char *end;

        static_assert(sizeof(val) >= sizeof(uint32_t), "unsigned long is less than 32 bits");

        errno = 0;
        val = strtoul(string, &end, 10);
        if (errno != 0) {
                if (errno == ERANGE)
                        return UTIL_STRING_E_RANGE;

                return error_origin(-errno);
        } else if (*end || string == end) {
                return UTIL_STRING_E_INVALID;
        } else if (val > UINT32_MAX) {
                return UTIL_STRING_E_RANGE;
        }

        *valp = val;

        return 0;
}

int util_strtou64(uint64_t *valp, const char *string) {
        unsigned long long val;
        char *end;

        static_assert(sizeof(val) >= sizeof(uint64_t), "unsigned long long is less than 64 bits");

        errno = 0;
        val = strtoull(string, &end, 10);
        if (errno != 0) {
                if (errno == ERANGE)
                        return UTIL_STRING_E_RANGE;

                return error_origin(-errno);
        } else if (*end || string == end) {
                return UTIL_STRING_E_INVALID;
        } else if (val > UINT64_MAX) {
                return UTIL_STRING_E_RANGE;
        }

        *valp = val;

        return 0;
}

int util_strtoint(int *valp, const char *string) {
        long val;
        char *end;

        errno = 0;
        val = strtol(string, &end, 10);
        if (errno != 0) {
                if (errno == ERANGE)
                        return UTIL_STRING_E_RANGE;

                return error_origin(-errno);
        } else if (*end || string == end) {
                return UTIL_STRING_E_INVALID;
        } else if (val > INT_MAX || val < INT_MIN) {
                return UTIL_STRING_E_RANGE;
        }

        *valp = val;

        return 0;
}
