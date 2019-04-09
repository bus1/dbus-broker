/*
 * DBus Protocol Constants and Definitions
 */

#include <c-stdaux.h>
#include <stdlib.h>
#include "dbus/protocol.h"

static bool dbus_validate_name_common(const char *name, size_t n_name, bool namespace) {
        bool has_dot = false, dot = true, unique = false;
        size_t i;

        if (n_name > 255)
                return false;

        if (n_name > 0 && name[0] == ':') {
                ++name;
                --n_name;
                unique = true;
        }

        for (i = 0; i < n_name; ++i) {
                if (name[i] == '.') {
                        if (dot)
                                return false;

                        has_dot = true;
                        dot = true;
                } else if (_c_unlikely_(!((name[i] >= 'a' && name[i] <= 'z') ||
                                          (name[i] >= 'A' && name[i] <= 'Z') ||
                                          (name[i] >= '0' && name[i] <= '9' && (!dot || unique)) ||
                                          name[i] == '_' ||
                                          name[i] == '-'))) {
                        return false;
                } else {
                        dot = false;
                }
        }

        return (has_dot || namespace) && !dot;
}

/**
 * dbus_validate_name() - verify validity of bus name
 * @name:               name
 * @n_name:             length of name
 *
 * This verifies the validity of the passed bus name.
 *
 * Return: True if @name is a valid bus name, false otherwise.
 */
bool dbus_validate_name(const char *name, size_t n_name) {
        return dbus_validate_name_common(name, n_name, false);
}

/**
 * dbus_validate_namespace() - verify validity of bus namespace
 * @namespace:          namespace
 * @n_namespace:        length of namespace
 *
 * This verifies the validity of the passed bus namespace.
 *
 * Return: True if @namespace is a valid bus namespace, false otherwise.
 */
bool dbus_validate_namespace(const char *namespace, size_t n_namespace) {
        return dbus_validate_name_common(namespace, n_namespace, true);
}

/**
 * dbus_validate_interface() - verify validity of interface
 * @interface           interface
 * @n_interface:        length of interface
 *
 * This verifies the validity of the passed interface.
 *
 * Return: True if @interface is a valid interface, false otherwise.
 */
bool dbus_validate_interface(const char *interface, size_t n_interface) {
        bool has_dot = false, dot = true;
        size_t i;

        if (n_interface > 255)
                return false;

        for (i = 0; i < n_interface; ++i) {
                if (interface[i] == '.') {
                        if (dot)
                                return false;

                        has_dot = true;
                        dot = true;
                } else if (_c_unlikely_(!((interface[i] >= 'a' && interface[i] <= 'z') ||
                                          (interface[i] >= 'A' && interface[i] <= 'Z') ||
                                          (interface[i] >= '0' && interface[i] <= '9' && !dot) ||
                                          interface[i] == '_'))) {
                        return false;
                } else {
                        dot = false;
                }
        }

        return has_dot && !dot;
}

/**
 * dbus_validate_member() - verify validity of member
 * @member              member
 * @n_member:           length of interface
 *
 * This verifies the validity of the passed member.
 *
 * Return: True if @member is a valid member, false otherwise.
 */
bool dbus_validate_member(const char *member, size_t n_member) {
        bool first = true;
        size_t i;

        if (n_member > 255)
                return false;

        for (i = 0; i < n_member; ++i) {
                if (_c_unlikely_(!((member[i] >= 'a' && member[i] <= 'z') ||
                                   (member[i] >= 'A' && member[i] <= 'Z') ||
                                   (member[i] >= '0' && member[i] <= '9' && !first) ||
                                   member[i] == '_')))
                        return false;
                first = false;
        }

        return !first;
}

/**
 * dbus_validate_error_name() - verify validity of error_name
 * @name:               error name
 * @n_name:             length of error name
 *
 * This verifies the validity of the passed error name.
 *
 * Return: True if @name is a valid error name, false otherwise.
 */
bool dbus_validate_error_name(const char *name, size_t n_name) {
        return dbus_validate_interface(name, n_name);
}
