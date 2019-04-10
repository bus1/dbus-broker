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

#include <c-stdaux.h>
#include <stdlib.h>
#include "dbus/address.h"

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
 *
 * This function does not fully validate the address! All it does is to detect
 * the type of address, but the address might still be invalid. In other words,
 * this function correctly assigns a type to all valid addresses. However, in
 * case of invalid addresses, it might give false positives. That is, for the
 * sake of distinguishing addresses, this is sufficient. However, for the sake
 * of data validation when creating/acquiring names, you need to further verify
 * the validity of the name.
 */
void address_from_string(Address *address, const char *string) {
        uint64_t id;
        char *end;

        address->type = ADDRESS_TYPE_OTHER;

        if (!string[0]) {
                return;
        } else if (string[0] == ':') {
                if (strncmp(string, ":1.", strlen(":1.")))
                        return;

                string += strlen(":1.");
                errno = 0;
                id = strtoull(string, &end, 10);
                if (end == string || *end || errno || id == ULLONG_MAX)
                        return;

                address->type = ADDRESS_TYPE_ID;
                address->id = id;
        } else {
                address->type = ADDRESS_TYPE_NAME;
                address->name = string;
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
                c_assert(r >= 0 && r < (ssize_t)sizeof(address->buffer));
                return address->buffer;
        case ADDRESS_TYPE_NAME:
                return address->name;
        default:
                c_assert(0);
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
                c_assert(r >= 0 && r < (ssize_t)n_buffer);
                break;
        case ADDRESS_TYPE_NAME:
                c_assert(n_buffer > strlen(address->name));
                strcpy(buffer, address->name);
                break;
        default:
                c_assert(0);
                strcpy(buffer, ":<garbage>");
                break;
        }
}
