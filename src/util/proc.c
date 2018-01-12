/*
 * Proc Helpers
 */

#include <c-macro.h>
#include <stdlib.h>
#include <stdio.h>
#include "util/error.h"
#include "util/proc.h"

/*
 * XXX: The kernel should be made to handle SO_PEERSEC also on
 *      socketpair sockets, making this redundant.
 */
int proc_get_seclabel(char **labelp, size_t *n_labelp) {
        _c_cleanup_(c_fclosep) FILE *f = NULL;
        char buffer[LINE_MAX] = {}, *c, *label;

        f = fopen("/proc/self/attr/current", "re");
        if (f) {
                errno = 0;
                if (!fgets(buffer, sizeof(buffer), f)) {
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
