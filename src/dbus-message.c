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
        uint64_t n_data = 0;

        if (_c_likely_(header.endian == 'l')) {
                n_data += c_align8((uint64_t)le32toh(header.n_args));
                n_data += (uint64_t)le32toh(header.n_body);
        } else if (header.endian == 'B') {
                n_data += c_align8((uint64_t)be32toh(header.n_args));
                n_data += (uint64_t)be32toh(header.n_body);
        } else {
                return -EBADMSG;
        }

        if (n_data + sizeof(header) > DBUS_MESSAGE_SIZE_MAX)
                return -EMSGSIZE;

        message = malloc(sizeof(*message) + c_align8(n_data));
        if (!message)
                return -ENOMEM;

        message->n_refs = C_REF_INIT;
        message->big_endian = (header.endian == 'B');
        message->n_fds = 0;
        message->fds = NULL;
        message->n_data = n_data;
        message->n_copied = 0;
        message->header = header;

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
