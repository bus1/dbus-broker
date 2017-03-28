#pragma once

/*
 * D-Bus Variants
 */

#include <c-macro.h>
#include <stdlib.h>

typedef struct DBusVariantType DBusVariantType;

/*
 * DBUS_VARIANT_TYPE_?: Those macros are initializers for builtin types. They
 *                      can be used to initialize DBusVariantType objects, if
 *                      needed.
 *                      Note that these are given as tuples, so you might have
 *                      to strip the surrounding brackets (via C_EXPAND or
 *                      similar).
 */
#define DBUS_VARIANT_TYPE_b (1, 0, 'b', 1, 1)
#define DBUS_VARIANT_TYPE_y (4, 2, 'y', 1, 1)
#define DBUS_VARIANT_TYPE_n (2, 1, 'n', 1, 1)
#define DBUS_VARIANT_TYPE_q (2, 1, 'q', 1, 1)
#define DBUS_VARIANT_TYPE_i (4, 2, 'i', 1, 1)
#define DBUS_VARIANT_TYPE_u (4, 2, 'u', 1, 1)
#define DBUS_VARIANT_TYPE_x (8, 3, 'x', 1, 1)
#define DBUS_VARIANT_TYPE_t (8, 3, 't', 1, 1)
#define DBUS_VARIANT_TYPE_h (4, 2, 'h', 1, 1)
#define DBUS_VARIANT_TYPE_d (8, 3, 'd', 1, 1)
#define DBUS_VARIANT_TYPE_s (0, 2, 's', 1, 1)
#define DBUS_VARIANT_TYPE_o (0, 2, 'o', 1, 1)
#define DBUS_VARIANT_TYPE_g (0, 0, 'g', 1, 1)
#define DBUS_VARIANT_TYPE_v (0, 0, 'v', 1, 0)

/*
 * DBUS_VARIANT_TYPE_LENGTH_MAX: Maximum length of a DBus Type Signature, given
 *                               in number of characters (without terminating
 *                               0).
 * DBUS_VARIANT_TYPE_DEPTH_MAX: Maximum depth of a DBus Type Signature.
 * DBUS_VARIANT_TYPE_SIZE_BITS: Number of bits available to store the fixed
 *                              size of a DBus type.
 */
#define DBUS_VARIANT_TYPE_LENGTH_MAX (255)
#define DBUS_VARIANT_TYPE_DEPTH_MAX (64)
#define DBUS_VARIANT_TYPE_SIZE_BITS (11)

/*
 * struct DBusVariantType - Type Information
 * @size:               Size of this type, or 0 if not fixed-size. Note that
 *                      the size of a type is always a multiple of its
 *                      alignment.
 * @alignment:          Alignment of this type, given as a power of 2.
 * @element:            Element identifier, 0 if invalid.
 * @length:             Length of this type, given in number of structures.
 * @basic:              Whether or not this is a basic type.
 */
struct DBusVariantType {
        uint32_t size : DBUS_VARIANT_TYPE_SIZE_BITS;
        uint32_t alignment : 2;
        uint32_t element : 8;
        uint32_t length : 8;
        uint32_t basic : 1;
};

long dbus_variant_type_new_from_signature(DBusVariantType **infop,
                                          const char *signature,
                                          size_t n_signature);
