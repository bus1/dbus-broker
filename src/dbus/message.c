/*
 * D-Bus Messages
 */

#include <c-dvar.h>
#include <c-dvar-type.h>
#include <c-macro.h>
#include <c-ref.h>
#include <endian.h>
#include <stdlib.h>
#include "dbus/message.h"
#include "dbus/protocol.h"
#include "util/fdlist.h"
#include "util/error.h"

static_assert(_DBUS_MESSAGE_FIELD_N <= 8 * sizeof(unsigned int), "Header fields exceed bitmap");

static int message_new(Message **messagep, bool big_endian, size_t n_extra) {
        _c_cleanup_(message_unrefp) Message *message = NULL;

        message = malloc(sizeof(*message) + c_align8(n_extra));
        if (!message)
                return error_origin(-ENOMEM);

        message->n_refs = C_REF_INIT;
        message->big_endian = big_endian;
        message->allocated_data = false;
        message->fds = NULL;
        message->n_data = 0;
        message->n_copied = 0;
        message->n_header = 0;
        message->n_body = 0;
        message->data = NULL;
        message->header = NULL;
        message->body = NULL;

        *messagep = message;
        message = NULL;
        return 0;
}

/**
 * message_new_incoming() - XXX
 */
int message_new_incoming(Message **messagep, MessageHeader header) {
        _c_cleanup_(message_unrefp) Message *message = NULL;
        uint64_t n_header, n_body, n_data;
        int r;

        if (_c_likely_(header.endian == 'l')) {
                n_header = sizeof(header) + (uint64_t)le32toh(header.n_fields);
                n_body = (uint64_t)le32toh(header.n_body);
        } else if (header.endian == 'B') {
                n_header = sizeof(header) + (uint64_t)be32toh(header.n_fields);
                n_body = (uint64_t)be32toh(header.n_body);
        } else {
                return MESSAGE_E_CORRUPT_HEADER;
        }

        n_data = c_align8(n_header) + n_body;
        if (n_data > MESSAGE_SIZE_MAX)
                return MESSAGE_E_TOO_LARGE;

        r = message_new(&message, (header.endian == 'B'), n_data);
        if (r)
                return error_trace(r);

        message->n_data = n_data;
        message->n_header = n_header;
        message->n_body = n_body;
        message->data = message + 1;
        message->header = (void *)message->data;
        message->body = message->data + c_align8(n_header);
        message->vecs[0] = (struct iovec){ message->header, c_align8(n_header) };
        message->vecs[1] = (struct iovec){ NULL, 0 };
        message->vecs[2] = (struct iovec){ message->body, n_body };

        message->n_copied += sizeof(header);
        memcpy(message->data, &header, sizeof(header));

        *messagep = message;
        message = NULL;
        return 0;
}

/**
 * message_new_outgoing() - XXX
 */
int message_new_outgoing(Message **messagep, void *data, size_t n_data) {
        _c_cleanup_(message_unrefp) Message *message = NULL;
        MessageHeader *header = data;
        uint64_t n_header, n_body;
        int r;

        assert(n_data >= sizeof(MessageHeader));
        assert(!((unsigned long)data & 0x7));
        assert((header->endian == 'B') == (__BYTE_ORDER == __BIG_ENDIAN) &&
               (header->endian == 'l') == (__BYTE_ORDER == __LITTLE_ENDIAN));
        assert(n_data >= sizeof(MessageHeader) + c_align8(header->n_fields));

        n_header = sizeof(MessageHeader) + header->n_fields;
        n_body = n_data - c_align8(n_header);

        header->n_body = n_data - sizeof(MessageHeader) - c_align8(header->n_fields);

        r = message_new(&message, (header->endian == 'B'), 0);
        if (r)
                return error_trace(r);

        message->allocated_data = true;
        message->n_data = n_data;
        message->n_header = n_header;
        message->n_body = n_body;
        message->data = data;
        message->header = (void *)message->data;
        message->body = message->data + c_align8(n_header);
        message->vecs[0] = (struct iovec){ message->header, c_align8(n_header) };
        message->vecs[1] = (struct iovec){ NULL, 0 };
        message->vecs[2] = (struct iovec){ message->body, n_body };

        *messagep = message;
        message = NULL;
        return 0;
}

/* internal callback for message_unref() */
void message_free(_Atomic unsigned long *n_refs, void *userdata) {
        Message *message = c_container_of(n_refs, Message, n_refs);

        if (message->allocated_data)
                free(message->data);
        fdlist_free(message->fds);
        free(message);
}

/**
 * message_parse_metadata() - XXX
 */
int message_parse_metadata(Message *message, MessageMetadata *metadata) {
        static const CDVarType type[] = {
                C_DVAR_T_INIT(
                        C_DVAR_T_TUPLE7(
                                C_DVAR_T_y,
                                C_DVAR_T_y,
                                C_DVAR_T_y,
                                C_DVAR_T_y,
                                C_DVAR_T_u,
                                C_DVAR_T_u,
                                C_DVAR_T_ARRAY(
                                        C_DVAR_T_TUPLE2(
                                                C_DVAR_T_y,
                                                C_DVAR_T_v
                                        )
                                )
                        )
                ), /* (yyyyuua(yv)) */
        };
        _c_cleanup_(c_dvar_deinitp) CDVar v = CDVAR_NULL;
        unsigned int mask;
        uint8_t field;
        int r;

        *metadata = (MessageMetadata){};

        c_dvar_begin_read(&v, message->big_endian, type, 1, message->header, message->n_header);

        /*
         * Validate static header fields. Byte-order and body-length are part
         * of the stream-validation, and skipped here. The others are:
         *   type:
         *       Anything but "INVALID" is accepted.
         *   flags:
         *       Anything is accepted.
         *   version:
         *       Must be '1'.
         *   serial:
         *       Anything but 0 is accepted.
         */

        c_dvar_read(&v, "(yyyyuu[",
                    NULL,
                    &metadata->header.type,
                    &metadata->header.flags,
                    &metadata->header.version,
                    NULL,
                    &metadata->header.serial);

        if (metadata->header.type == DBUS_MESSAGE_TYPE_INVALID)
                return MESSAGE_E_INVALID_HEADER;
        if (metadata->header.version != 1)
                return MESSAGE_E_INVALID_HEADER;
        if (!metadata->header.serial)
                return MESSAGE_E_INVALID_HEADER;

        /*
         * Validate header fields one-by-one. We follow exactly what
         * dbus-daemon(1) does:
         *   - Unknown fields are ignored
         *   - Duplicates are rejected (except if they are unknown)
         *   - Types must match expected types
         *
         * Additionally, each header field has some restrictions on its own
         * validity.
         */

        while (c_dvar_more(&v)) {
                c_dvar_read(&v, "(y", &field);

                if (field >= _DBUS_MESSAGE_FIELD_N) {
                        c_dvar_skip(&v, "v)");
                        continue;
                }

                if (metadata->fields.available & (1U << field))
                        return MESSAGE_E_INVALID_HEADER;

                metadata->fields.available |= 1U << field;

                switch (field) {
                case DBUS_MESSAGE_FIELD_INVALID:
                        return MESSAGE_E_INVALID_HEADER;

                case DBUS_MESSAGE_FIELD_PATH:
                        c_dvar_read(&v, "<o>)", c_dvar_type_o, &metadata->fields.path);

                        if (!strcmp(metadata->fields.path, "/org/freedesktop/DBus/Local"))
                                return MESSAGE_E_INVALID_HEADER;

                        break;

                case DBUS_MESSAGE_FIELD_INTERFACE:
                        c_dvar_read(&v, "<s>)", c_dvar_type_s, &metadata->fields.interface);

                        if (!strcmp(metadata->fields.interface, "org.freedesktop.DBus.Local"))
                                return MESSAGE_E_INVALID_HEADER;

                        /* XXX: invalid interfaces are rejected */

                        break;

                case DBUS_MESSAGE_FIELD_MEMBER:
                        c_dvar_read(&v, "<s>)", c_dvar_type_s, &metadata->fields.member);
                        /* XXX: invalid members are rejected */
                        break;

                case DBUS_MESSAGE_FIELD_ERROR_NAME:
                        c_dvar_read(&v, "<s>)", c_dvar_type_s, &metadata->fields.error_name);
                        /* XXX: Invalid error-names are rejected */
                        break;

                case DBUS_MESSAGE_FIELD_REPLY_SERIAL:
                        c_dvar_read(&v, "<u>)", c_dvar_type_u, &metadata->fields.reply_serial);
                        if (!metadata->fields.reply_serial)
                                return MESSAGE_E_INVALID_HEADER;
                        break;

                case DBUS_MESSAGE_FIELD_DESTINATION:
                        c_dvar_read(&v, "<s>)", c_dvar_type_s, &metadata->fields.destination);
                        /* XXX: Invalid bus-names are rejected */
                        break;

                case DBUS_MESSAGE_FIELD_SENDER:
                        c_dvar_read(&v, "<s>)", c_dvar_type_s, &metadata->fields.sender);
                        /* XXX: Invalid bus-names are rejected */
                        break;

                case DBUS_MESSAGE_FIELD_SIGNATURE:
                        c_dvar_read(&v, "<g>)", c_dvar_type_g, &metadata->fields.signature);
                        break;

                case DBUS_MESSAGE_FIELD_UNIX_FDS:
                        c_dvar_read(&v, "<u>)", c_dvar_type_u, &metadata->fields.unix_fds);

                        if (metadata->fields.unix_fds > fdlist_count(message->fds))
                                return MESSAGE_E_INVALID_HEADER;

                        break;

                default:
                        return error_origin(-ENOTRECOVERABLE);
                }
        }

        /*
         * Check mandatory fields. That is, depending on the message types, all
         * mandatory fields must be present.
         */

        switch (metadata->header.type) {
        case DBUS_MESSAGE_TYPE_METHOD_CALL:
                mask = (1U << DBUS_MESSAGE_FIELD_PATH) |
                       (1U << DBUS_MESSAGE_FIELD_MEMBER);
                break;
        case DBUS_MESSAGE_TYPE_METHOD_RETURN:
                mask = (1U << DBUS_MESSAGE_FIELD_REPLY_SERIAL);
                break;
        case DBUS_MESSAGE_TYPE_ERROR:
                mask = (1U << DBUS_MESSAGE_FIELD_ERROR_NAME) |
                       (1U << DBUS_MESSAGE_FIELD_REPLY_SERIAL);
                break;
        case DBUS_MESSAGE_TYPE_SIGNAL:
                mask = (1U << DBUS_MESSAGE_FIELD_PATH) |
                       (1U << DBUS_MESSAGE_FIELD_INTERFACE) |
                       (1U << DBUS_MESSAGE_FIELD_MEMBER);
                break;
        default:
                mask = 0;
                break;
        }

        if ((metadata->fields.available & mask) != mask)
                return MESSAGE_E_INVALID_HEADER;

        /*
         * Finish the variant parser. If anything went wobbly in between, we
         * will be told here.
         */

        c_dvar_read(&v, "])");

        r = c_dvar_end_read(&v);
        if (r > 0)
                return MESSAGE_E_INVALID_HEADER;
        else if (r)
                return error_fold(r);

        /*
         * XXX: Validate body!
         */

        /*
         * dbus-daemon(1) only ever fetches the correct number of FDs from its
         * stream. This violates the D-Bus specification, which requires FDs to
         * be sent together with the message, and in a single hunk. Therefore,
         * we try to stick to dbus-daemon(1) behavior as close as possible, by
         * rejecting if the requested count exceeds the passed count. However,
         * we always discard any remaining FDs silently.
         */
        if (message->fds)
                fdlist_truncate(message->fds, metadata->fields.unix_fds);

        return 0;
}
