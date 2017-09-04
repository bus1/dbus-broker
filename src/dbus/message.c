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
#include "util/log.h"
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
        message->parsed = false;
        message->sender_id = ADDRESS_ID_INVALID;
        message->fds = NULL;
        message->n_data = 0;
        message->n_copied = 0;
        message->n_header = 0;
        message->n_body = 0;
        message->data = NULL;
        message->header = NULL;
        message->metadata = (MessageMetadata){};
        message->body = NULL;
        message->original_sender = NULL;

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
        message->vecs[2] = (struct iovec){ NULL, 0 };
        message->vecs[3] = (struct iovec){ message->body, n_body };

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
        message->vecs[2] = (struct iovec){ NULL, 0 };
        message->vecs[3] = (struct iovec){ message->body, n_body };

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

static int message_parse_header(Message *message, MessageMetadata *metadata) {
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
        _c_cleanup_(c_dvar_deinit) CDVar v = C_DVAR_INIT;
        unsigned int mask;
        uint8_t field;
        int r;

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

                        /* cache sender in case it needs to be stitched out */
                        message->original_sender = (void *)metadata->fields.sender;
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
         * Fix up the signature. The DBus spec states that missing signatures
         * should be treated as empty.
         */

        metadata->fields.signature = metadata->fields.signature ?: "";

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

        return 0;
}

static int message_parse_body(Message *message, MessageMetadata *metadata) {
        _c_cleanup_(c_dvar_deinit) CDVar v = C_DVAR_INIT;
        const char *signature = metadata->fields.signature;
        size_t i, n_signature, n_types;
        CDVarType *t, *types;
        int r;

        /*
         * Parse body-signature into CDVarType array. We use a single array
         * with all the argument-types concatenated.
         */

        n_signature = strlen(signature);
        assert(n_signature < 256);
        types = alloca(n_signature * sizeof(CDVarType));
        n_types = 0;

        for (i = 0; i < n_signature; i += types[i].length) {
                t = types + i;
                r = c_dvar_type_new_from_signature(&t, signature + i, n_signature - i);
                if (r)
                        return r < 0 ? error_origin(r) : MESSAGE_E_INVALID_HEADER;

                ++n_types;
        }

        /*
         * Now that we know the argument types, use c_dvar_skip() to verify
         * them. While at it, cache all the string/path arguments, so the match
         * rule processing can access them directly.
         */

        c_dvar_begin_read(&v, message->big_endian, types, n_types, message->body, message->n_body);

        for (i = 0, t = types; i < n_types; ++i, t += t->length) {
                switch (t->element) {
                case 's':
                case 'o':
                        if (i < C_ARRAY_SIZE(metadata->args)) {
                                metadata->args[i].element = t->element;
                                c_dvar_read(&v, (char[2]){ t->element, 0 }, &metadata->args[i].value);
                                break;
                        }

                        /* fallthrough */
                default:
                        c_dvar_skip(&v, "*");
                        break;
                }
        }

        r = c_dvar_end_read(&v);
        if (r)
                return r < 0 ? error_origin(r) : MESSAGE_E_INVALID_BODY;

        return 0;
}

/**
 * message_parse_metadata() - XXX
 */
int message_parse_metadata(Message *message) {
        void *p;
        int r;

        assert(!message->parsed);

        /*
         * As first step, parse the static header and the dynamic header
         * fields. Any error there is fatal.
         */
        r = message_parse_header(message, &message->metadata);
        if (r)
                return error_trace(r);

        /*
         * Validate the padding between the header and body. Those must be 0!
         * We usually wouldn't care but must be compatible to dbus-daemon(1),
         * so lets verify them.
         */
        for (p = (void *)message->header + message->n_header; p < message->body; ++p)
                if (*(const uint8_t *)p)
                        return MESSAGE_E_INVALID_HEADER;

        /*
         * Now that the header is validated, we read through the message body.
         * Again, this is required for compatibility with dbus-daemon(1), but
         * also to fetch the arguments for match-filters used by eavesdropping
         * and common broadcasts.
         */
        r = message_parse_body(message, &message->metadata);
        if (r)
                return error_trace(r);

        /*
         * dbus-daemon(1) only ever fetches the correct number of FDs from its
         * stream. This violates the D-Bus specification, which requires FDs to
         * be sent together with the message, and in a single hunk. Therefore,
         * we try to stick to dbus-daemon(1) behavior as close as possible, by
         * rejecting if the requested count exceeds the passed count. However,
         * we always discard any remaining FDs silently.
         */
        if (message->fds)
                fdlist_truncate(message->fds, message->metadata.fields.unix_fds);

        message->parsed = true;
        return 0;
}

/**
 * message_stitch_sender() - stitch in new sender field
 * @message:                    message to operate on
 * @sender_id:                  sender id to stitch in
 *
 * When the broker forwards messages, it needs to fill in the sender-field
 * reliably. Unfortunately, this requires modifying the fields-array of the
 * D-Bus header. Since we do not want to re-write the entire array, we allow
 * some stitching magic here to happen.
 *
 * This means, we use some nice properties of tuple-arrays in the D-Bus
 * marshalling (namely, they're 8-byte aligned, thus statically discoverable
 * when we know the offset), and simply cut out the existing sender field and
 * append a new one.
 *
 * This function must not be called more than once on any message (it will
 * throw a fatal error). Furthermore, this will cut the message in parts, such
 * that it is no longer readable linearly. However, none of the fields are
 * relocated nor overwritten. That is, any cached pointer stays valid, though
 * maybe no longer part of the actual message.
 */
void message_stitch_sender(Message *message, uint64_t sender_id) {
        size_t n, n_stitch, n_field, n_sender;
        const char *sender;
        void *end, *field;

        /*
         * Must not be called more than once. We reserve the 2 iovecs between
         * the original header and body to stitch the sender field. The caller
         * must have parsed the metadata before.
         */
        assert(message->parsed);
        assert(!message->vecs[1].iov_base && !message->vecs[1].iov_len);
        assert(!message->vecs[2].iov_base && !message->vecs[2].iov_len);

        /*
         * Convert the sender id to a unique name. This should never fail on
         * a valid sender id.
         */
        sender = address_to_string(&(Address)ADDRESS_INIT_ID(sender_id));
        message->sender_id = sender_id;

        /*
         * Calculate string, field, and buffer lengths. We need to possibly cut
         * out a `(yv)' and insert another one at the end. See the D-Bus
         * marshalling for details, but shortly this means:
         *
         *     - Tuples are always 8-byte aligned. Hence, we can reliably
         *       calculate field offsets.
         *
         *     - A string-field needs `1 + 3 + 4 + n + 1' bytes:
         *
         *         - length of 'y':                 1
         *         - length of 'v':                 3 + 4 + n + 1
         *           - type 'g' needs:
         *             - size field byte:           1
         *             - type string 's':           1
         *             - zero termination:          1
         *           - sender string needs:
         *             - alignment to 4:            0
         *             - size field int:            4
         *             - sender string:             n
         *             - zero termination:          1
         */
        n_sender = strlen(sender);
        n_field = 1 + 3 + 4 + n_sender + 1;
        n_stitch = c_align8(n_field);

        /*
         * The patch buffer is pre-allocated. Verify its size is sufficient to
         * hold the stitched sender.
         */
        assert(n_stitch <= sizeof(message->patch));
        assert(n_sender <= ADDRESS_ID_STRING_MAX);
        static_assert(1 + 3 + 4 + ADDRESS_ID_STRING_MAX + 1 <= sizeof(message->patch),
                      "Message patch buffer has insufficient size");

        if (message->original_sender) {
                /*
                 * If @message already has a sender field, we need to remove it
                 * first, so we can append the correct sender. The message
                 * parser cached the start of a possible sender field as
                 * @message->original_sender (pointing to the start of the
                 * sender string!). Hence, calculate the offset to its
                 * surrounding field and cut it out.
                 * See above for size-calculations of `(yv)' fields.
                 */
                n = strlen(message->original_sender);
                end = (void *)message->header + c_align8(message->n_header);
                field = message->original_sender - (1 + 3 + 4);

                assert(message->original_sender >= (void *)message->header);
                assert(message->original_sender + n + 1 <= end);

                /* fold remaining fields into following vector */
                message->vecs[1].iov_base = field + c_align8(1 + 3 + 4 + n + 1);
                message->vecs[1].iov_len = message->vecs[0].iov_len;
                message->vecs[1].iov_len -= message->vecs[1].iov_base - message->vecs[0].iov_base;

                /* cut field from previous vector */
                message->vecs[0].iov_len = field - message->vecs[0].iov_base;

                /*
                 * @message->n_header as well as @message->header->n_fields are
                 * screwed here, but fixed up below.
                 *
                 * Note that we cannot fix them here, since we can only
                 * calculate them if we actually append data. Otherwise, we
                 * cannot know the length of the last field, and as such cannot
                 * subtract the trailing padding.
                 */
        }

        /*
         * Now that any possible sender field was cut out, we can append the
         * new sender field at the end. The 3rd iovec is reserved for that
         * purpose.
         */

        message->vecs[2].iov_base = message->patch;
        message->vecs[2].iov_len = n_stitch;

        /* fill in `(yv)' with sender and padding */
        message->patch[0] = DBUS_MESSAGE_FIELD_SENDER;
        message->patch[1] = 1;
        message->patch[2] = 's';
        message->patch[3] = 0;
        if (message->big_endian)
                memcpy(message->patch + 4, (uint32_t[1]){ htobe32(n_sender) }, sizeof(uint32_t));
        else
                memcpy(message->patch + 4, (uint32_t[1]){ htole32(n_sender) }, sizeof(uint32_t));
        memcpy(message->patch + 8, sender, n_sender + 1);
        memset(message->patch + 8 + n_sender + 1, 0, n_stitch - n_field);

        /*
         * After we cut the previous sender field and inserted the new, adjust
         * all the size-counters in the message again.
         */

        message->n_header = message->vecs[0].iov_len +
                            message->vecs[1].iov_len +
                            n_field;
        message->n_data = c_align8(message->n_header) + message->n_body;

        if (message->big_endian)
                message->header->n_fields = htobe32(message->n_header - sizeof(*message->header));
        else
                message->header->n_fields = htole32(message->n_header - sizeof(*message->header));
}

void message_log_append(Message *message, Log *log) {
        log_appendf(log,
                    "DBUS_BROKER_MESSAGE_DESTINATION=%s\n"
                    "DBUS_BRKOER_MESSAGE_SERIAL=%d\n"
                    "DBUS_BROKER_MESSAGE_SIGNATURE=%s\n",
                    message->metadata.fields.destination ?: "<broadcast>",
                    message->metadata.header.serial,
                    message->metadata.fields.signature ?: "<missing>");

        switch (message->metadata.header.type) {
        case DBUS_MESSAGE_TYPE_METHOD_CALL:
                log_appendf(log,
                            "DBUS_BROKER_MESSAGE_TYPE=method_call\n"
                            "DBUS_BROKER_MESSAGE_PATH=%s\n"
                            "DBUS_BRKOER_MESSAGE_INTERFACE=%s\n"
                            "DBUS_BROKER_MESSAGE_MEMBER=%s\n",
                            message->metadata.fields.path ?: "<missing>",
                            message->metadata.fields.interface ?: "<missing>",
                            message->metadata.fields.member ?: "<missing>");
                break;
        case DBUS_MESSAGE_TYPE_SIGNAL:
                log_appendf(log,
                            "DBUS_BROKER_MESSAGE_TYPE=signal\n"
                            "DBUS_BROKER_MESSAGE_PATH=%s\n"
                            "DBUS_BROKER_MESSAGE_INTERFACE=%s\n"
                            "DBUS_BROKER_MESSAGE_MEMBER=%s\n",
                            message->metadata.fields.path ?: "<missing>",
                            message->metadata.fields.interface ?: "<missing>",
                            message->metadata.fields.member ?: "<missing>");
                break;
        case DBUS_MESSAGE_TYPE_METHOD_RETURN:
                log_appendf(log,
                            "DBUS_BROKER_MESSAGE_TYPE=method_return\n"
                            "MESSAGE_REPLY_SERIAL=%d\n",
                            message->metadata.fields.reply_serial);
                break;
        case DBUS_MESSAGE_TYPE_ERROR:
                log_appendf(log,
                            "DBUS_BROKER_MESSAGE_TYPE=method_return\n"
                            "DBUS_BROKER_MESSAGE_ERROR_NAME=%s\n"
                            "DBUS_BROKER_MESSAGE_REPLY_SERIAL=%d\n",
                            message->metadata.fields.error_name,
                            message->metadata.fields.reply_serial);
                break;
        default:
                log_appendf(log, "DBUS_BROKER_MESSAGE_TYPE=%u\n", message->metadata.header.type);
        }
}
