/*
 * D-Bus Messages
 */

#include <c-macro.h>
#include <c-ref.h>
#include <endian.h>
#include <stdlib.h>
#include "message.h"
#include "util/fdlist.h"

static int message_new(Message **messagep, bool big_endian, size_t n_extra) {
        _c_cleanup_(message_unrefp) Message *message = NULL;

        message = malloc(sizeof(*message) + c_align8(n_extra));
        if (!message)
                return -ENOMEM;

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
                return MESSAGE_E_CORRUPT_HEADER;

        r = message_new(&message, (header.endian == 'B'), n_data);
        if (r)
                return r;

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
                return r;

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
