/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: D-Bus Broker Developers */

/*
 * String Helpers
 */

#include <c-stdaux.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "util/error.h"
#include "util/string.h"

/*
 * `strtoul()` and `strtoull()` silently accept a leading minus sign and return
 * the negated value modulo 2^n. Since our unsigned parsers must never turn
 * `-1` into `UINT32_MAX`/`UINT64_MAX`, reject such input explicitly. Leading
 * whitespace is skipped by the C library, so skip it here as well before
 * looking at the sign.
 */
static bool util_string_is_negative(const char *string) {
        return string[strspn(string, " \t\n\v\f\r")] == '-';
}

int util_strtou32(uint32_t *valp, const char *string) {
        unsigned long val;
        char *end;

        static_assert(sizeof(val) >= sizeof(uint32_t), "unsigned long is less than 32 bits");

        if (util_string_is_negative(string))
                return UTIL_STRING_E_INVALID;

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

        if (util_string_is_negative(string))
                return UTIL_STRING_E_INVALID;

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
