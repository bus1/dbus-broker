/*
 * Bus SELinux Helpers
 */

#include <c-macro.h>
#include <stdlib.h>
#include "util/selinux.h"

bool bus_selinux_is_enabled(void) {
        return false;
}

int bus_selinux_sid_init(BusSELinuxSID *sid, const char *seclabel) {
        return 0;
}

int bus_selinux_new(BusSELinux **selinuxp, const char *seclabel) {
        *selinuxp = NULL;
        return 0;
}

BusSELinux *bus_selinux_free(BusSELinux *selinux) {
        return NULL;
}

int bus_selinux_add_name(BusSELinux *selinux, const char *name, const char *seclabel) {
        return 0;
}

int bus_selinux_check_own(BusSELinux *selinux,
                          BusSELinuxSID *sid_owner,
                          const char *name) {
        return 0;
}

int bus_selinux_check_send(BusSELinux *selinux,
                           BusSELinuxSID *sid_sender,
                           BusSELinuxSID *sid_receiver) {
        return 0;
}
