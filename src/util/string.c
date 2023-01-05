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

void generate_args_string(bool valid_arg, char **ret, int size, int *cur_i, char *option, char *val) {
        int i = *cur_i;

        if (!valid_arg)
                return;

        if (i + 3 >= size)
                return;

        ret[i++] = option;
        ret[i++] = val;
        *cur_i = i;
}

/* This extract value in @string to @ret.
@string: string splited by ";"
@ret: value between ";""
input example: 1;2;3
output example: 1 => 2 => 3 (one by one) */
char *extract_word_inlist(char *string, char **ret) {
        int i = 0, length = strlen(string);
        bool found_value = false;
        while (i < length) {
                if (string[i] != ';')
                        found_value = true;
                else {
                        if (found_value)
                                break;
                        else {
                                string++;
                                length--;
                                continue;
                        }
                }
                i++;
        }
        if (!found_value) {
                **ret = 0;
                return NULL;
        }
        c_assert(i >= 0);
        *ret = strncpy(*ret, string, i);
        *(*ret + i) = '\0';
        return string + i;
}

/* Like extract_word_inlist, see example below:
input example: [{a}{b}{c}]
output example: a => b => c (one by one). */
char *extract_list_element(char *string, char **ret)
{
        if (!string || strlen(string) <= 2)
                return NULL;
        int i = 0, pi = 0;
        bool valid_left = false;
        while (i < strlen(string)) {
                if (string[i] == '{') {
                        pi = i + 1;
                        valid_left = true;
                } else if (string[i] == '}') {
                        valid_left = (i == pi ? false : valid_left);
                        if (valid_left)
                                break;
                }
                i++;
        }
        if (!valid_left) {
                **ret = 0;
                return NULL;
        }
        c_assert(i >= pi);
        *ret = strndup(string + pi, i - pi);
        return string + i + 1;
}
