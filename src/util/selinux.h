#pragma once

/*
 * Bus SELinux Helpers
 */

#include <c-macro.h>
#include <stdlib.h>

typedef struct BusSELinuxRegistry BusSELinuxRegistry;
typedef struct BusSELinuxID BusSELinuxID;

enum {
        _SELINUX_E_SUCCESS,

        SELINUX_E_DENIED,
};

bool bus_selinux_is_enabled(void);
const char *bus_selinux_policy_root(void);

int bus_selinux_id_init(BusSELinuxID **id, const char *seclabel);

int bus_selinux_registry_new(BusSELinuxRegistry **registryp, BusSELinuxID *fallback_id);
BusSELinuxRegistry *bus_selinux_registry_ref(BusSELinuxRegistry *registry);
BusSELinuxRegistry *bus_selinux_registry_unref(BusSELinuxRegistry *registry);

C_DEFINE_CLEANUP(BusSELinuxRegistry *, bus_selinux_registry_unref);

int bus_selinux_registry_add_name(BusSELinuxRegistry *registry, const char *name, const char *context);

int bus_selinux_check_own(BusSELinuxRegistry *registry,
                          BusSELinuxID *id_owner,
                          const char *name);
int bus_selinux_check_send(BusSELinuxRegistry *registry,
                           BusSELinuxID *id_sender,
                           BusSELinuxID *id_receiver);

int bus_selinux_init_global(void);
void bus_selinux_deinit_global(void);
