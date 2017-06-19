/*
 * D-Bus Peer Addresses
 *
 * The D-Bus message broker requires peers to always address the destination of
 * their messages. Those addresses can come in different styles. The 'Address'
 * type implemented here parses or writes such addresses, hiding the details
 * behind a simple API.
 *
 * The 'Address' type is supposed to live on the stack. It can be initialized
 * either from one of the source addresses (a unique ID, a well-known name, ..)
 * or it can parse a user-supplied string.
 * The structure is open-coded and can be accesses directly. It consists of a
 * 'type' field that identifies the address type, and a union carrying the
 * parsed data.
 */

#include <c-macro.h>
#include <stdlib.h>
#include "dbus/address.h"

static bool address_verify_name(const char *name, size_t n_name) {
        bool has_dot = false, dot = true;
        size_t i;

        if (n_name > 255)
                return false;

        for (i = 0; i < n_name; ++i) {
                if (name[i] == '.') {
                        if (dot)
                                return false;

                        has_dot = true;
                        dot = true;
                } else if (_c_unlikely_(!((name[i] >= 'a' && name[i] <= 'z') ||
                                          (name[i] >= 'A' && name[i] <= 'Z') ||
                                          (name[i] >= '0' && name[i] <= '9' && !dot) ||
                                          name[i] == '_' ||
                                          name[i] == '-'))) {
                        return false;
                } else {
                        dot = false;
                }
        }

        return has_dot && !dot;
}

/**
 * address_init_from_id() - initialize ID address
 * @address:            address to operate on
 * @id:                 ID to use
 *
 * This initializes the address @address to be of type ADDRESS_TYPE_ID with ID
 * @id.
 */
void address_init_from_id(Address *address, uint64_t id) {
        *address = (Address)ADDRESS_INIT_ID(id);
}

/**
 * address_init_from_name() - initialize name address
 * @address:            address to operate on
 * @name:               name to use
 *
 * This initializes the address @address to be of type ADDRESS_TYPE_NAME with
 * name @name.
 *
 * Note that @name is *NOT* copied into @address. That is, the lifetime of
 * @address is bound to @name.
 */
void address_init_from_name(Address *address, const char *name) {
        *address = (Address)ADDRESS_INIT_NAME(name);
}

/**
 * address_from_string() - initialize address from string representation
 * @address:            address to operate on
 * @string:             string to use
 *
 * This initializes @address from the string representation of an address,
 * given as @string. On return, @address->type will contain the type of the
 * address that was given as @string. Note that this might be
 * ADDRESS_TYPE_OTHER, in case the parser couldn't detect the address type.
 *
 * Note that @string is *NOT* copied into @address, but might be referenced
 * from it. Hence, the lifetime of @address is bound to @string.
 */
void address_from_string(Address *address, const char *string) {
        uint64_t id;
        char *end;

        if (!strncmp(string, ":1.", strlen(":1."))) {
                string += strlen(":1.");

                errno = 0;
                id = strtoull(string, &end, 10);
                if (end == string || *end || errno || id == ULLONG_MAX) {
                        address->type = ADDRESS_TYPE_OTHER;
                } else {
                        address->type = ADDRESS_TYPE_ID;
                        address->id = id;
                }
        } else if (address_verify_name(string, strlen(string))) {
                address->type = ADDRESS_TYPE_NAME;
                address->name = string;
        } else {
                address->type = ADDRESS_TYPE_OTHER;
        }
}

/**
 * address_to_string() - return string representation of an address
 * @address:            address to operate on
 *
 * This returns a pointer to the string representation of @address. Note that
 * the caller must make sure @address is a valid address. If @address is of
 * type ADDRESS_TYPE_OTHER, this will raise a fatal exception.
 *
 * Note that the address buffer is bound to @address. That is, whenever
 * @address is modified, the returned pointer will become invalid.
 *
 * Return: Pointer to string representation of @address.
 */
const char *address_to_string(Address *address) {
        int r;

        switch (address->type) {
        case ADDRESS_TYPE_ID:
                r = snprintf(address->buffer, sizeof(address->buffer), ":1.%"PRIu64, address->id);
                assert(r >= 0 && r < (ssize_t)sizeof(address->buffer));
                return address->buffer;
        case ADDRESS_TYPE_NAME:
                return address->name;
        default:
                assert(0);
                return ":<garbage>";
        }
}

/**
 * address_write() - write string representation of an address
 * @address:            address to operate on
 * @buffer:             buffer to write into
 * @n_buffer:           size of @buffer
 *
 * This is similar to address_to_string(), but rather than returning a pointer
 * to an internal buffer, it writes the address to a caller-supplied buffer.
 *
 * Note that the caller must provide a suitably sized buffer. If the buffer is
 * not big enough to hold the string representation, this will raise a fatal
 * exception.
 */
void address_write(Address *address, char *buffer, size_t n_buffer) {
        int r;

        switch (address->type) {
        case ADDRESS_TYPE_ID:
                r = snprintf(buffer, n_buffer, ":1.%"PRIu64, address->id);
                assert(r >= 0 && r < (ssize_t)n_buffer);
                break;
        case ADDRESS_TYPE_NAME:
                assert(n_buffer > strlen(address->name));
                strcpy(buffer, address->name);
                break;
        default:
                assert(0);
                strcpy(buffer, ":<garbage>");
                break;
        }
}
