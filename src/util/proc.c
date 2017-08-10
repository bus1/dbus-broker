/*
 * Proc Helpers
 */

#include <c-macro.h>
#include <stdlib.h>
#include <stdio.h>
#include "util/error.h"
#include "util/proc.h"

/* XXX: the kernel should be made to handle SO_PEERSEC also on
 *      socketpair sockets, making this redundant.
 */
int proc_get_seclabel(char **labelp, size_t *lenp) {
        _c_cleanup_(c_fclosep) FILE *f = NULL;
        char buffer[LINE_MAX], *label, *c;

        f = fopen("/proc/self/attr/current", "re");
        if (!f) {
                if (errno == ENOENT) {
                        if (labelp)
                                *labelp = NULL;
                        if (lenp)
                                *lenp = 0;
                        return 0;
                }

                return error_origin(-errno);
        }

        if (!fgets(buffer, sizeof(buffer), f)) {
                if (ferror(f)) {
                        if (errno > 0)
                                return error_origin(-errno);
                        else
                                return error_origin(-ENOTRECOVERABLE);
                }

                c = buffer;
        } else {
                c = strchr(buffer, '\n');
        }

        if (c)
                *c = '\0';

        label = strdup(buffer);
        if (!label)
                return error_origin(-ENOMEM);

        if (labelp)
                *labelp = label;
        if (lenp)
                *lenp = strlen(label);
        return 0;
}

