#pragma once

/*
 * D-Bus Messages
 */

#include <c-macro.h>
#include <c-ref.h>
#include <stdlib.h>

typedef struct DBusMessage DBusMessage;
typedef struct DBusMessageHeader DBusMessageHeader;

#define DBUS_MESSAGE_SIZE_MAX (128UL * 1024UL * 1024UL) /* taken from spec */

struct DBusMessageHeader {
        uint8_t endian;
        uint8_t type;
        uint8_t flags;
        uint8_t version;
        uint32_t n_body;
        uint32_t serial;
        uint32_t n_fields;
} _c_packed_;

struct DBusMessage {
        _Atomic unsigned long n_refs;

        bool big_endian : 1;

        size_t n_fds;
        int *fds;

        size_t n_body;
        size_t n_data;
        size_t n_copied;

        DBusMessageHeader *header;
        void *fields;
        void *body;

        char data[];
};

int dbus_message_new(DBusMessage **messagep, DBusMessageHeader header);
void dbus_message_free(_Atomic unsigned long *n_refs, void *userdata);

/**
 * dbus_message_ref() - XXX
 */
static inline DBusMessage *dbus_message_ref(DBusMessage *message) {
        if (message)
                c_ref_inc(&message->n_refs);
        return message;
}

/**
 * dbus_message_unref() - XXX
 */
static inline DBusMessage *dbus_message_unref(DBusMessage *message) {
        if (message)
                c_ref_dec(&message->n_refs, dbus_message_free, NULL);
        return NULL;
}

C_DEFINE_CLEANUP(DBusMessage *, dbus_message_unref);
