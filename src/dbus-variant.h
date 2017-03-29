#pragma once

/*
 * D-Bus Variants
 */

#include <c-macro.h>
#include <stdlib.h>

typedef struct DBusVariant DBusVariant;
typedef struct DBusVariantLevel DBusVariantLevel;
typedef struct DBusVariantType DBusVariantType;

/*
 * DBUS_VARIANT_TYPE_?: Those macros are initializers for builtin types. They
 *                      can be used to initialize DBusVariantType objects, if
 *                      needed.
 *                      Note that these are given as tuples, so you might have
 *                      to strip the surrounding brackets (via C_EXPAND or
 *                      similar).
 */
#define DBUS_VARIANT_TYPE_y (1, 0, 'y', 1, 1)
#define DBUS_VARIANT_TYPE_b (4, 2, 'b', 1, 1)
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
 * DBUS_VARIANT_SIZE_MAX_SHIFT: Maximum size of a DBus Variant, given as power
 *                              of 2 (`shift value'). Note that this is taken
 *                              from the maximum DBus message size, since DBus
 *                              Variants are used in no other context.
 *
 * DBUS_VARIANT_SIZE_INITIAL_SHIFT: Initial size of the pre-allocated buffer
 *                                  when writing DBus Variants, given as power
 *                                  of 2.
 *                                  XXX: This is set to page-size right now,
 *                                       but should really be chosen by average
 *                                       message sizes on a real system.
 */
#define DBUS_VARIANT_SIZE_MAX_SHIFT (27)
#define DBUS_VARIANT_SIZE_INITIAL_SHIFT (12)

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

/**
 * struct DBusVariantLevel - XXX
 */
struct DBusVariantLevel {
        const DBusVariantType *root_type;
        const DBusVariantType *i_type;
        uint8_t n_type;
        uint8_t container;
        size_t i_buffer;
        size_t n_buffer;
};

/**
 * struct DBusVariant - XXX
 */
struct DBusVariant {
        uint8_t *buffer;
        size_t n_buffer;

        int poison;
        bool ro : 1;
        bool big_endian : 1;

        DBusVariantLevel *current;
        DBusVariantLevel levels[DBUS_VARIANT_TYPE_DEPTH_MAX + 1];
};

#define DBUS_VARIANT_INIT(_var, _type) {                \
                .current = (_var).levels,               \
                .levels[0].root_type = (_type),         \
                .levels[0].i_type = (_type),            \
                .levels[0].n_type = (_type)->length,    \
        }

void dbus_variant_init(DBusVariant *var, const DBusVariantType *type);
void dbus_variant_deinit(DBusVariant *var);

void dbus_variant_parse(DBusVariant *var, bool big_endian, const void *data, size_t n_data);
void dbus_variant_reset(DBusVariant *var);
int dbus_variant_rewind(DBusVariant *var);
int dbus_variant_steal(DBusVariant *var, void **datap, size_t *n_datap);

bool dbus_variant_more(DBusVariant *var);
void dbus_variant_vread(DBusVariant *var, const char *format, va_list args);
void dbus_variant_vwrite(DBusVariant *var, const char *format, va_list args);

C_DEFINE_CLEANUP(DBusVariant *, dbus_variant_deinit);
