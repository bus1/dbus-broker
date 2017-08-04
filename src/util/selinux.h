#pragma once

/*
 * Bus SELinux Helpers
 */

#include <c-macro.h>
#include <stdlib.h>

typedef struct BusSELinux BusSELinux;
typedef struct BusSELinuxSID BusSELinuxSID;

enum {
        _SELINUX_E_SUCCESS,

        SELINUX_E_DENIED,
};

bool bus_selinux_is_enabled(void);

int bus_selinux_sid_init(BusSELinuxSID **sid, const char *seclabel);

int bus_selinux_new(BusSELinux **selinuxp, const char *seclabel);
BusSELinux *bus_selinux_free(BusSELinux *selinux);

C_DEFINE_CLEANUP(BusSELinux *, bus_selinux_free);

int bus_selinux_add_name(BusSELinux *selinux, const char *name, const char *seclabel);

int bus_selinux_check_own(BusSELinux *selinux,
                          BusSELinuxSID *sid_owner,
                          const char *name);
int bus_selinux_check_send(BusSELinux *selinux,
                           BusSELinuxSID *sid_sender,
                           BusSELinuxSID *sid_receiver);
