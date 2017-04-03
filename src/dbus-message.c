/*
 * D-Bus Messages
 */

#include <c-macro.h>
#include <c-ref.h>
#include <endian.h>
#include <stdlib.h>
#include "dbus-message.h"

/**
 * dbus_message_new() - XXX
 */
int dbus_message_new(DBusMessage **messagep, DBusMessageHeader header) {
        _c_cleanup_(dbus_message_unrefp) DBusMessage *message = NULL;
        uint64_t n_header, n_body, n_data;

        if (_c_likely_(header.endian == 'l')) {
                n_header = sizeof(header) + (uint64_t)le32toh(header.n_fields);
                n_body = (uint64_t)le32toh(header.n_body);
        } else if (header.endian == 'B') {
                n_header = sizeof(header) + (uint64_t)be32toh(header.n_fields);
                n_body = (uint64_t)be32toh(header.n_body);
        } else {
                return -EBADMSG;
        }

        n_data = c_align8(n_header) + n_body;

        if (n_data > DBUS_MESSAGE_SIZE_MAX)
                return -EMSGSIZE;

        message = malloc(sizeof(*message) + c_align8(n_data));
        if (!message)
                return -ENOMEM;

        message->n_refs = C_REF_INIT;
        message->big_endian = (header.endian == 'B');
        message->n_fds = 0;
        message->fds = NULL;
        message->n_header = n_header;
        message->n_body = n_body;
        message->n_data = n_data;
        message->n_copied = sizeof(header);
        message->header = (void *)message->data;
        message->body = message->data + c_align8(n_header);
        memcpy(message->data, &header, sizeof(header));

        *messagep = message;
        message = NULL;
        return 0;
}

/* internal callback for dbus_message_unref() */
void dbus_message_free(_Atomic unsigned long *n_refs, void *userdata) {
        DBusMessage *message = c_container_of(n_refs, DBusMessage, n_refs);

        while (message->n_fds > 0)
                close(message->fds[--message->n_fds]);

        free(message->fds);
        free(message);
}
