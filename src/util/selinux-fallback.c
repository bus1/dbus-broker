/*
 * Bus SELinux Fallback Helpers
 *
 * This fallback is used when libselinux is not available, and is meant to be
 * functionally equivalent to util/selinux.c in case SELinux is disabled, but
 * without requiring the library.
 *
 * See util/selinux.c for details.
 */

#include <c-stdaux.h>
#include <stdlib.h>
#include "util/selinux.h"

bool bus_selinux_is_enabled(void) {
        return false;
}

bool bus_selinux_is_enforcing(void) {
        return false;
}

const char *bus_selinux_policy_root(void) {
        return NULL;
}

int bus_selinux_registry_new(BusSELinuxRegistry **registryp, const char *fallback_context) {
        *registryp = NULL;
        return 0;
}

BusSELinuxRegistry *bus_selinux_registry_ref(BusSELinuxRegistry *registry) {
        return NULL;
}

BusSELinuxRegistry *bus_selinux_registry_unref(BusSELinuxRegistry *registry) {
        return NULL;
}

int bus_selinux_registry_add_name(BusSELinuxRegistry *registry, const char *name, const char *context) {
        return 0;
}

int bus_selinux_check_own(BusSELinuxRegistry *registry,
                          const char *owner_context,
                          const char *name) {
        return 0;
}

int bus_selinux_check_send(BusSELinuxRegistry *registry,
                           const char *context_sender,
                           const char *context_receiver) {
        return 0;
}

int bus_selinux_init_global(void) {
        return 0;
}

void bus_selinux_deinit_global(void) {
        return;
}
