#pragma once

/*
 * D-Bus Messages
 */

#include <c-macro.h>
#include <c-ref.h>
#include <stdlib.h>
#include "dbus/address.h"
#include "dbus/protocol.h"

typedef struct FDList FDList;
typedef struct Message Message;
typedef struct MessageHeader MessageHeader;
typedef struct MessageMetadata MessageMetadata;

/* max message size; taken from spec */
#define MESSAGE_SIZE_MAX (128UL * 1024UL * 1024UL)

/* max patch buffer size; see message_stitch_sender() */
#define MESSAGE_PATCH_MAX (C_ALIGN_TO(1 + 3 + 4 + ADDRESS_ID_STRING_MAX + 1, 8))

enum {
        _MESSAGE_E_SUCCESS,

        MESSAGE_E_CORRUPT_HEADER,
        MESSAGE_E_TOO_LARGE,
        MESSAGE_E_INVALID_HEADER,
        MESSAGE_E_INVALID_BODY,
};

struct MessageMetadata {
        struct {
                uint8_t type;
                uint8_t flags;
                uint8_t version;
                uint32_t serial;
        } header;

        struct {
                unsigned int available;
                const char *path;
                const char *interface;
                const char *member;
                const char *error_name;
                uint32_t reply_serial;
                const char *destination;
                const char *sender;
                const char *signature;
                uint32_t unix_fds;
        } fields;

        struct {
                char element;
                const void *value;
        } args[64];
};

struct Message {
        _Atomic unsigned long n_refs;

        bool big_endian : 1;
        bool allocated_data : 1;
        bool parsed : 1;

        uint64_t sender_id;

        FDList *fds;

        size_t n_data;
        size_t n_copied;
        size_t n_header;
        size_t n_body;

        void *data;
        MessageHeader *header;
        MessageMetadata metadata;
        void *body;

        void *original_sender;
        struct iovec vecs[4];
        alignas(uint64_t) uint8_t patch[MESSAGE_PATCH_MAX];
};

struct MessageHeader {
        uint8_t endian;
        uint8_t type;
        uint8_t flags;
        uint8_t version;
        uint32_t n_body;
        uint32_t serial;
        uint32_t n_fields;
} _c_packed_;

int message_new_incoming(Message **messagep, MessageHeader header);
int message_new_outgoing(Message **messagep, void *data, size_t n_data);
void message_free(_Atomic unsigned long *n_refs, void *userdata);

int message_parse_metadata(Message *message);
void message_stitch_sender(Message *message, uint64_t sender_id);

/* inline helpers */

/**
 * message_ref() - XXX
 */
static inline Message *message_ref(Message *message) {
        if (message)
                c_ref_inc(&message->n_refs);
        return message;
}

/**
 * message_unref() - XXX
 */
static inline Message *message_unref(Message *message) {
        if (message)
                c_ref_dec(&message->n_refs, message_free, NULL);
        return NULL;
}

/**
 * message_read_serial() - XXX
 */
static inline uint32_t message_read_serial(Message *message) {
        if (message->header->type != DBUS_MESSAGE_TYPE_METHOD_CALL ||
            _c_unlikely_(message->header->flags & DBUS_HEADER_FLAG_NO_REPLY_EXPECTED))
                return 0;

        if (_c_likely_(!message->big_endian))
                return le32toh(message->header->serial);
        else
                return be32toh(message->header->serial);
}

C_DEFINE_CLEANUP(Message *, message_unref);
