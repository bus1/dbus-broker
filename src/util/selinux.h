#pragma once

/*
 * Bus SELinux Helpers
 */

#include <c-stdaux.h>
#include <stdlib.h>

typedef struct BusSELinuxRegistry BusSELinuxRegistry;

enum {
        _SELINUX_E_SUCCESS,

        SELINUX_E_DENIED,
};

bool bus_selinux_is_enabled(void);
bool bus_selinux_is_enforcing(void);
const char *bus_selinux_policy_root(void);

int bus_selinux_registry_new(BusSELinuxRegistry **registryp, const char *fallback_context);
BusSELinuxRegistry *bus_selinux_registry_ref(BusSELinuxRegistry *registry);
BusSELinuxRegistry *bus_selinux_registry_unref(BusSELinuxRegistry *registry);

C_DEFINE_CLEANUP(BusSELinuxRegistry *, bus_selinux_registry_unref);

int bus_selinux_registry_add_name(BusSELinuxRegistry *registry, const char *name, const char *context);

int bus_selinux_check_own(BusSELinuxRegistry *registry,
                          const char *context_owner,
                          const char *name);
int bus_selinux_check_send(BusSELinuxRegistry *registry,
                           const char *context_sender,
                           const char *context_receiver);

int bus_selinux_init_global(void);
void bus_selinux_deinit_global(void);
