#pragma once

#include "launch/launcher.h"

int object_supports_interface(Launcher *launcher, const char *bus_name, const char *object, const char *interface_name);
