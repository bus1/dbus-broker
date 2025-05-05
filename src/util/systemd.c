/*
 * Systemd Utilities
 */

#include <c-stdaux.h>
#include <stdlib.h>
#include "util/error.h"
#include "util/systemd.h"

static bool needs_escape(char c) {
        return !strchr("0123456789"
                       "abcdefghijklmnopqrstuvwxyz"
                       "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                       ":_.", c);
}

static char *escape_char(char *t, char c) {
        // Include terminating NUL to silence warnings about truncated strings.
        static const char table[17] = "0123456789abcdef";

        *t++ = '\\';
        *t++ = 'x';
        *t++ = table[(c >> 4) & 0x0f];
        *t++ = table[c & 0x0f];

        return t;
}

/**
 * systemd_escape_unit() - escape unit name
 * @escapedp:           output argument for escaped unit name
 * @unescaped:          unescaped unit name to operate with
 *
 * This escapes the specified systemd unit name and returns it in the specified
 * output pointer.
 *
 * Return: 0 on success, negative error code on failure.
 */
int systemd_escape_unit(char **escapedp, const char *unescaped) {
        char *buffer, *dst;
        const char *src;

        buffer = malloc(strlen(unescaped) * 4 + 1);
        if (!buffer)
                return error_origin(-ENOMEM);

        src = unescaped;
        dst = buffer;

        if (*src == '.')
                dst = escape_char(dst, *src++);

        for ( ; *src; ++src) {
                if (*src == '/')
                        *dst++ = '-';
                else if (needs_escape(*src))
                        dst = escape_char(dst, *src);
                else
                        *dst++ = *src;
        }

        *dst = 0;
        *escapedp = buffer;
        return 0;
}
