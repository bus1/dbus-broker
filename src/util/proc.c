/*
 * Proc Helpers
 */

#include <c-stdaux.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include "util/error.h"
#include "util/proc.h"

int proc_get_seclabel(pid_t pid, char **labelp, size_t *n_labelp) {
        _c_cleanup_(c_fclosep) FILE *f = NULL;
        char path[64], buffer[LINE_MAX] = {}, *c, *label;

        if (pid == PROC_SELF)
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
