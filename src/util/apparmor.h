#pragma once

/*
 * Bus AppArmor Helpers
 */

#include <stdlib.h>

int bus_apparmor_is_enabled(bool *enabledp);
int bus_apparmor_dbus_supported(bool *supportedp);
