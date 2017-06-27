/*
 * DBus Protocol Constants and Definitions
 */

#include <c-macro.h>
#include <stdlib.h>
#include "dbus/protocol.h"

/**
 * dbus_validate_name() - verify validity of well-known name
 * @name:               name
 * @n_name:             length of name
 *
 * This verifies the validity of the passed well-known name.
 *
 * Return: True if @name is a valid well-known name, false otherwise.
 */
bool dbus_validate_name(const char *name, size_t n_name) {
        bool has_dot = false, dot = true;
        size_t i;

        if (n_name > 255)
                return false;

        for (i = 0; i < n_name; ++i) {
                if (name[i] == '.') {
                        if (dot)
                                return false;

                        has_dot = true;
                        dot = true;
                } else if (_c_unlikely_(!((name[i] >= 'a' && name[i] <= 'z') ||
                                          (name[i] >= 'A' && name[i] <= 'Z') ||
                                          (name[i] >= '0' && name[i] <= '9' && !dot) ||
                                          name[i] == '_' ||
                                          name[i] == '-'))) {
                        return false;
                } else {
                        dot = false;
                }
        }

        return has_dot && !dot;
}
