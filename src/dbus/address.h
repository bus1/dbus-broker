#pragma once

/*
 * D-Bus Peer Addresses
 */

#include <c-stdaux.h>
#include <stdlib.h>

typedef struct Address Address;

enum {
        ADDRESS_TYPE_OTHER,
        ADDRESS_TYPE_ID,
        ADDRESS_TYPE_NAME,
        _ADDRESS_TYPE_N,
};

/* invalid ID address */
#define ADDRESS_ID_INVALID (ULLONG_MAX)
/* max length of string representation of ID addresses */
#define ADDRESS_ID_STRING_MAX (3 + C_DECIMAL_MAX(uint64_t))

struct Address {
        unsigned int type;
        char buffer[ADDRESS_ID_STRING_MAX + 1];
        union {
                uint64_t id;
                const char *name;
        };
};

#define ADDRESS_NULL { .type = _ADDRESS_TYPE_OTHER }
#define ADDRESS_INIT_ID(_id) { .type = ADDRESS_TYPE_ID, .id = (_id) }
#define ADDRESS_INIT_NAME(_name) { .type = ADDRESS_TYPE_NAME, .name = (_name) }

void address_init_from_id(Address *address, uint64_t id);
void address_init_from_name(Address *address, const char *name);

void address_from_string(Address *address, const char *string);
const char *address_to_string(Address *address);

void address_write(Address *address, char *buffer, size_t n_buffer);
