#pragma once

/*
 * D-Bus Messages
 */

#include <c-macro.h>
#include <c-ref.h>
#include <stdlib.h>

typedef struct Message Message;
typedef struct MessageHeader MessageHeader;

#define MESSAGE_SIZE_MAX (128UL * 1024UL * 1024UL) /* taken from spec */

struct MessageHeader {
        uint8_t endian;
        uint8_t type;
        uint8_t flags;
        uint8_t version;
        uint32_t n_body;
        uint32_t serial;
        uint32_t n_fields;
} _c_packed_;

struct Message {
        _Atomic unsigned long n_refs;

        bool big_endian : 1;

        size_t n_fds;
        int *fds;

        size_t n_header;
        size_t n_body;
        size_t n_data;
        size_t n_copied;

        MessageHeader *header;
        void *body;

        char data[];
};

int message_new(Message **messagep, MessageHeader header);
void message_free(_Atomic unsigned long *n_refs, void *userdata);

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
