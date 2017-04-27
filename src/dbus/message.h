#pragma once

/*
 * D-Bus Messages
 */

#include <c-macro.h>
#include <c-ref.h>
#include <stdlib.h>

typedef struct FDList FDList;
typedef struct Message Message;
typedef struct MessageHeader MessageHeader;
typedef struct MessageMetadata MessageMetadata;

#define MESSAGE_SIZE_MAX (128UL * 1024UL * 1024UL) /* taken from spec */

enum {
        _MESSAGE_E_SUCCESS,

        MESSAGE_E_CORRUPT_HEADER,
        MESSAGE_E_TOO_LARGE,
        MESSAGE_E_INVALID_HEADER,
};

struct Message {
        _Atomic unsigned long n_refs;

        bool big_endian : 1;
        bool allocated_data : 1;
        bool parsed : 1;

        FDList *fds;

        size_t n_data;
        size_t n_copied;
        size_t n_header;
        size_t n_body;

        void *data;
        MessageHeader *header;
        void *body;
        void *sender;
        struct iovec vecs[4];
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
};

int message_new_incoming(Message **messagep, MessageHeader header);
int message_new_outgoing(Message **messagep, void *data, size_t n_data);
void message_free(_Atomic unsigned long *n_refs, void *userdata);

int message_parse_metadata(Message *message, MessageMetadata *metadata);
int message_stitch_sender(Message *message, const char *sender);

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

C_DEFINE_CLEANUP(Message *, message_unref);
