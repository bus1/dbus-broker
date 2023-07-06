/*
 * Proc Helpers
 */

#include <c-stdaux.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include "util/error.h"
#include "util/proc.h"

/**
 * proc_field() - Extract individual field from proc-text-file
 * @data:       content of the file
 * @key:        key to find
 * @valuep:     output variable to store the duplicated value
 *
 * Search through a key-value proc-file for the specified key and return the
 * value as newly allocated string.
 *
 * The caller is responsible to free the value via `free()`.
 *
 * The proc-file must be a standard text-file with no embedded string
 * terminators. It is the caller's responsibility to use this only on
 * suitable files.
 *
 * Return: 0 on success, PROC_E_NOT_FOUND if the key was not found, and
 *         negative error code on failure.
 */
int proc_field(const char *data, const char *key, char **valuep) {
        const size_t n_key = strlen(key);
        const char *pos, *t;
        char *value;

        pos = data;
        do {
                do {
                        /* Find next occurrence of they key. */
                        t = strstr(pos, key);
                        if (!t)
                                return PROC_E_NOT_FOUND;

                        pos = t + n_key;

                        /* Continue if the key does not start a line. */
                } while (t != data && t[-1] != '\n');

                /* Skip possible whitespace before the colon. */
                pos += strspn(pos, " \t");

                /* Continue if the key is not complete. */
        } while (*pos != ':');

        /* Skip over the colon and whitespace. */
        ++pos;
        pos += strspn(pos, " \t");

        /* Extract the value. */
        value = strndup(pos, strcspn(pos, " \t\n\r"));
        if (!value)
                return error_origin(-ENOMEM);

        *valuep = value;
        return 0;
}

int proc_get_seclabel(pid_t pid, char **labelp, size_t *n_labelp) {
        _c_cleanup_(c_fclosep) FILE *f = NULL;
        char path[64], buffer[LINE_MAX] = {}, *c, *label;

        if (pid == PROC_PID_SELF)
                strcpy(path, "/proc/self/attr/current");
        else if (pid > 0)
                sprintf(path, "/proc/%"PRIu32"/attr/current", (uint32_t)pid);
        else
                return error_origin(-EINVAL);

        f = fopen(path, "re");
        if (f) {
                errno = 0;
                if (!fgets(buffer, sizeof(buffer), f)) {
                        /*
                         * If LSM core code is enabled, but no LSM is loaded,
                         * the kernel returns EINVAL. In that case, we treat
                         * the seclabel as empty string, similar to how the
                         * user-space LSM libraries do.
                         */
                        if (ferror(f) && errno != EINVAL)
                                return errno ? error_origin(-errno) : error_origin(-ENOTRECOVERABLE);
                }
        } else if (errno != ENOENT) {
                return error_origin(-errno);
        }

        c = strchrnul(buffer, '\n');
        label = strndup(buffer, c - buffer);
        if (!label)
                return error_origin(-ENOMEM);

        if (n_labelp)
                *n_labelp = strlen(label);
        *labelp = label;
        return 0;
}
