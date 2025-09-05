#pragma once

/*
 * Bus AppArmor Helpers
 */

#include <c-stdaux.h>
#include <stdlib.h>

typedef struct NameSet NameSet;

typedef struct BusAppArmorRegistry BusAppArmorRegistry;

enum {
        _BUS_APPARMOR_E_SUCCESS,

        BUS_APPARMOR_E_DENIED,
};

int bus_apparmor_is_enabled(bool *enabledp);
int bus_apparmor_dbus_supported(bool *supportedp);

int bus_apparmor_registry_new(struct BusAppArmorRegistry **registryp, const char *fallback_context);
BusAppArmorRegistry *bus_apparmor_registry_ref(BusAppArmorRegistry *registry);
BusAppArmorRegistry *bus_apparmor_registry_unref(BusAppArmorRegistry *registry);

C_DEFINE_CLEANUP(BusAppArmorRegistry *, bus_apparmor_registry_unref);

int bus_apparmor_set_bus_type(BusAppArmorRegistry *registry, const char *bustype);

int bus_apparmor_check_own(struct BusAppArmorRegistry *registry, const char *context,
                           const char *name);
int bus_apparmor_check_send(BusAppArmorRegistry *registry,
                            const char *sender_context, const char *receiver_context,
                            NameSet *subject, uint64_t subject_id,
                            const char *path, const char *interface, const char *method);
int bus_apparmor_check_eavesdrop(BusAppArmorRegistry *registry, const char *context);
