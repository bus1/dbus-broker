#pragma once

/*
 * DBus Protocol Constants
 */

#include <c-stdaux.h>
#include <stdlib.h>

enum {
    DBUS_NAME_FLAG_ALLOW_REPLACEMENT = (1ULL << 0),
    DBUS_NAME_FLAG_REPLACE_EXISTING  = (1ULL << 1),
    DBUS_NAME_FLAG_DO_NOT_QUEUE      = (1ULL << 2),
};

enum {
    DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER = 1,
    DBUS_REQUEST_NAME_REPLY_IN_QUEUE      = 2,
    DBUS_REQUEST_NAME_REPLY_EXISTS        = 3,
    DBUS_REQUEST_NAME_REPLY_ALREADY_OWNER = 4,
};

enum {
    DBUS_RELEASE_NAME_REPLY_RELEASED      = 1,
    DBUS_RELEASE_NAME_REPLY_NON_EXISTENT  = 2,
    DBUS_RELEASE_NAME_REPLY_NOT_OWNER     = 3,
};

enum {
    DBUS_START_REPLY_SUCCESS            = 1,
    DBUS_START_REPLY_ALREADY_RUNNING    = 2,
};

enum {
    DBUS_MESSAGE_TYPE_INVALID       = 0,
    DBUS_MESSAGE_TYPE_METHOD_CALL   = 1,
    DBUS_MESSAGE_TYPE_METHOD_RETURN = 2,
    DBUS_MESSAGE_TYPE_ERROR         = 3,
    DBUS_MESSAGE_TYPE_SIGNAL        = 4,
    _DBUS_MESSAGE_TYPE_N,
};

enum {
    DBUS_MESSAGE_FIELD_INVALID      = 0,
    DBUS_MESSAGE_FIELD_PATH         = 1,
    DBUS_MESSAGE_FIELD_INTERFACE    = 2,
    DBUS_MESSAGE_FIELD_MEMBER       = 3,
    DBUS_MESSAGE_FIELD_ERROR_NAME   = 4,
    DBUS_MESSAGE_FIELD_REPLY_SERIAL = 5,
    DBUS_MESSAGE_FIELD_DESTINATION  = 6,
    DBUS_MESSAGE_FIELD_SENDER       = 7,
    DBUS_MESSAGE_FIELD_SIGNATURE    = 8,
    DBUS_MESSAGE_FIELD_UNIX_FDS     = 9,
    _DBUS_MESSAGE_FIELD_N,
};

enum {
    DBUS_HEADER_FLAG_NO_REPLY_EXPECTED               = (1UL << 0),
    DBUS_HEADER_FLAG_NO_AUTO_START                   = (1UL << 1),
    DBUS_HEADER_FLAG_ALLOW_INTERACTIVE_AUTHORIZATION = (1UL << 2),
};

bool dbus_validate_name(const char *name, size_t n_name);
bool dbus_validate_namespace(const char *namespace, size_t n_namespace);
bool dbus_validate_interface(const char *interface, size_t n_interface);
bool dbus_validate_member(const char *member, size_t n_member);
bool dbus_validate_error_name(const char *name, size_t n_name);
