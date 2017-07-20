/*
 * SELinux Helpers
 */

#include <c-macro.h>
#include <selinux/selinux.h>
#include <stdlib.h>
#include "util/selinux.h"

bool selinux_is_enabled(void) {
        return (is_selinux_enabled() > 0);
}
