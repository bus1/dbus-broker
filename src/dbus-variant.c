/*
 * D-Bus Variants
 */

#include <byteswap.h>
#include <c-macro.h>
#include <endian.h>
#include <stdlib.h>
#include "dbus-variant.h"

_Static_assert(DBUS_VARIANT_TYPE_LENGTH_MAX * 8 < (1 << DBUS_VARIANT_TYPE_SIZE_BITS),
               "Not enough bits available to store fixed-size types");
_Static_assert(sizeof(DBusVariantType) == 4,
               "Unexpected padding in DBusVariantType");

const DBusVariantType dbus_variant_type_builtins[256] = {
        ['b'] = { C_EXPAND(DBUS_VARIANT_TYPE_b) },
        ['y'] = { C_EXPAND(DBUS_VARIANT_TYPE_y) },
        ['n'] = { C_EXPAND(DBUS_VARIANT_TYPE_n) },
        ['q'] = { C_EXPAND(DBUS_VARIANT_TYPE_q) },
        ['i'] = { C_EXPAND(DBUS_VARIANT_TYPE_i) },
        ['u'] = { C_EXPAND(DBUS_VARIANT_TYPE_u) },
        ['x'] = { C_EXPAND(DBUS_VARIANT_TYPE_x) },
        ['t'] = { C_EXPAND(DBUS_VARIANT_TYPE_t) },
        ['h'] = { C_EXPAND(DBUS_VARIANT_TYPE_h) },
        ['d'] = { C_EXPAND(DBUS_VARIANT_TYPE_d) },
        ['s'] = { C_EXPAND(DBUS_VARIANT_TYPE_s) },
        ['o'] = { C_EXPAND(DBUS_VARIANT_TYPE_o) },
        ['g'] = { C_EXPAND(DBUS_VARIANT_TYPE_g) },
        ['v'] = { C_EXPAND(DBUS_VARIANT_TYPE_v) },
};

/**
 * dbus_variant_type_new_from_signature() - XXX
 */
long dbus_variant_type_new_from_signature(DBusVariantType **infop,
                                          const char *signature,
                                          size_t n_signature) {
        _c_cleanup_(c_freep) DBusVariantType *info = NULL;
        DBusVariantType *container, *this;
        const DBusVariantType *builtin;
        DBusVariantType *stack[DBUS_VARIANT_TYPE_DEPTH_MAX];
        size_t i, i_container, n_type, depth;
        char c;

        /* reject overlong signatures right away */
        if (n_signature > DBUS_VARIANT_TYPE_LENGTH_MAX)
                return -EBADRQC;

        /*
         * As a first step, figure out how long the next type in @signature is.
         * This requires iterating the entire type, counting opening/closing
         * brackets. We do this up-front, with only limited type validation.
         * Knowing the final type-size allows pre-allocating @info.
         *
         * Note that empty signatures will be rejected by this. The caller is
         * responsible to check for empty signatures, otherwise you might end
         * up in infinite loops.
         */
        for (n_type = 0, depth = 0; n_type < n_signature; ++n_type) {
                if (signature[n_type] == 'a') {
                        continue;
                } else if (signature[n_type] == '(' ||
                           signature[n_type] == '{') {
                        ++depth;
                } else if (signature[n_type] == ')' ||
                           signature[n_type] == '}') {
                        if (!depth--)
                                return -EBADRQC;
                }

                if (!depth)
                        break;
        }

        if (n_type++ >= n_signature)
                return -EBADRQC;

        /*
         * Now that we know the type length, we pre-allocate @info and fill it
         * in.
         */
        info = malloc(sizeof(*info) * n_type);
        if (!info)
                return -ENOMEM;

        depth = 0;
        container = NULL;

        for (i = 0, depth = 0; i < n_type; ++i) {
                c = signature[i];
                this = &info[i];
                builtin = &dbus_variant_type_builtins[(uint8_t)c];
                i_container = container ? (container - info) : 0;

                /*
                 * In case our surrounding container is a DICT, we need to make
                 * sure that the _first_ following type is basic, and there are
                 * exactly 2 types following.
                 */
                if (container && container->element == '{') {
                        if (i_container + 2 > i) {
                                /* first type must be basic */
                                if (_c_unlikely_(!builtin->basic))
                                        return -EBADRQC;
                        } else if (i_container + 2 == i) {
                                /* there must be a second type */
                                if (_c_unlikely_(c == '}'))
                                        return -EBADRQC;
                        } else if (i_container + 2 < i) {
                                /* DICT is closed after second type */
                                if (_c_unlikely_(c != '}'))
                                        return -EBADRQC;
                        }
                }

                switch (c) {
                case '(':
                case '{':
                case 'a':
                        /* validate maximum depth */
                        if (_c_unlikely_(depth >= C_ARRAY_SIZE(stack)))
                                return -EBADRQC;

                        this->size = 0;
                        this->alignment = 2 + !!(c != 'a');
                        this->element = c;
                        this->length = 1 + (c != 'a');
                        this->basic = 0;

                        /*
                         * We opened a new container type, so continue with the
                         * next character. Skip handling terminal types below.
                         */
                        stack[depth++] = this;
                        container = this;
                        continue;

                case '}':
                case ')':
                        if (_c_unlikely_(!container || container->element != ((c == '}') ? '{' : '(')))
                                return -EBADRQC;

                        this->size = 0;
                        this->alignment = 0;
                        this->element = c;
                        this->length = 1;
                        this->basic = 0;
                        this = container;
                        container = --depth ? stack[depth - 1] : NULL;
                        break;

                default:
                        /* validate type existence */
                        if (_c_unlikely_(!builtin->element))
                                return -EBADRQC;

                        *this = *builtin;
                        break;
                }

                while (depth > 0 && container->element == 'a') {
                        container->length += this->length;

                        this = container;
                        container = --depth ? stack[depth - 1] : NULL;
                }

                if (depth > 0) {
                        if (this->size && (this == container + 1 || container->size)) {
                                container->size = C_ALIGN_TO(container->size, 1 << this->alignment);
                                container->size += this->size;
                        } else {
                                container->size = 0;
                        }

                        container->length += this->length;
                }

                if (!depth) {
                        *infop = info;
                        info = NULL;
                        return n_type;
                }
        }

        return -EBADRQC;
}

static bool dbus_variant_is_path(const char *str) {
        /* XXX: verify @str is a valid object path */
        return true;
}

static bool dbus_variant_is_signature(const char *str) {
        /* XXX: verify @str is a valid signature */
        return true;
}

void dbus_variant_init(DBusVariant *var, const DBusVariantType *type) {
        *var = (DBusVariant)DBUS_VARIANT_INIT(*var, type);
}

void dbus_variant_deinit(DBusVariant *var) {
        if (!var->ro)
                c_free(var->buffer);

        for ( ; var->current >= var->levels; --var->current)
                if (var->current->allocated_type)
                        c_free((void *)var->current->root_type);

        /* invalidate to prevent misuse */
        var->buffer = NULL;
        var->n_buffer = 0;
        var->current = NULL;
}

static void dbus_variant_root(DBusVariant *var) {
        for ( ; var->current >= var->levels; --var->current)
                if (var->current->allocated_type)
                        c_free((void *)var->current->root_type);

        var->current = var->levels;

        var->current->i_type = var->current->root_type;
        var->current->n_type = var->current->root_type->length;
        var->current->i_buffer = 0;
        var->current->n_buffer = var->n_buffer;
}

void dbus_variant_parse(DBusVariant *var, bool big_endian, const void *data, size_t n_data) {
        if (!var->ro)
                c_free(var->buffer);

        var->buffer = (void *)data;
        var->n_buffer = n_data;
        var->poison = 0;
        var->ro = true;
        var->big_endian = big_endian;
        dbus_variant_root(var);
}

void dbus_variant_reset(DBusVariant *var) {
        if (!var->ro)
                var->buffer = c_free(var->buffer);

        var->buffer = NULL;
        var->n_buffer = 0;
        var->poison = 0;
        var->ro = false;
        var->big_endian = false;
        dbus_variant_root(var);
}

int dbus_variant_rewind(DBusVariant *var) {
        if (var->poison)
                return var->poison;
        if (!var->ro || var->current != var->levels || var->current->n_type > 0)
                return var->poison = -ENOTRECOVERABLE;

        dbus_variant_root(var);
        return 0;
}

int dbus_variant_steal(DBusVariant *var, void **datap, size_t *n_datap) {
        if (var->poison)
                return var->poison;
        if (var->ro || var->current != var->levels || var->current->n_type > 0)
                return -ENOTRECOVERABLE;

        *datap = var->buffer;
        *n_datap = var->n_buffer;
        var->buffer = NULL;
        var->n_buffer = 0;

        dbus_variant_root(var);
        return 0;
}

bool dbus_variant_more(DBusVariant *var) {
        return var->ro && var->current->n_buffer;
}

static int dbus_variant_prepare_next(DBusVariant *var, char c) {
        char real_c;

        switch (c) {
        case '[':
        case '<':
        case '(':
        case '{':
                if (c == '[')
                        real_c = 'a';
                else if (c == '<')
                        real_c = 'v';

                if (var->current >= var->levels + C_ARRAY_SIZE(var->levels) - 1 ||
                    !var->current->n_type ||
                    var->current->i_type->element != real_c)
                        return -ENOTRECOVERABLE;

                /*
                 * Prepare container to enter with default values. Note
                 * that for enclosed types we must cut off the closing
                 * type as well (which is a dummy and has no value).
                 */
                (var->current + 1)->root_type = NULL;
                (var->current + 1)->i_type = var->current->i_type + 1;
                (var->current + 1)->n_type = var->current->n_type - 1 - (real_c == c);
                (var->current + 1)->container = real_c;
                (var->current + 1)->allocated_type = false;
                (var->current + 1)->i_buffer = var->current->i_buffer;
                (var->current + 1)->n_buffer = var->current->n_buffer;

                break;

        case ']':
        case '>':
        case ')':
        case '}':
                if (c == ']')
                        real_c = 'a';
                else if (c == '>')
                        real_c = 'v';
                else if (c == ')')
                        real_c = '(';
                else if (c == '}')
                        real_c = '{';

                if ((real_c != 'a' && var->current->n_type) ||
                    var->current->container != real_c)
                        return -ENOTRECOVERABLE;

                break;

        case 'a':
        case 'v':
                return -ENOTRECOVERABLE;

        default:
                if (!var->current->n_type ||
                    var->current->i_type->element != c)
                        return -ENOTRECOVERABLE;

                break;
        }

        return 0;
}

static int dbus_variant_read_data(DBusVariant *var, int alignment, const void **datap, size_t n_data) {
        size_t i, align;

        align = c_align_to(var->current->i_buffer, 1 << alignment) - var->current->i_buffer;

        if (_c_unlikely_(var->current->n_buffer < align + n_data))
                return -EBADMSG;

        /*
         * Verify alignment bytes are 0. Needed for compatibility with
         * dbus-daemon.
         */
        for (i = 0; i < align; ++i)
                if (_c_unlikely_(var->buffer[var->current->i_buffer + i]))
                        return -EBADMSG;

        *datap = var->buffer + var->current->i_buffer + align;
        var->current->i_buffer += align + n_data;
        var->current->n_buffer -= align + n_data;
        return 0;
}

static uint32_t dbus_variant_bswap16(DBusVariant *var, uint16_t v) {
        return _c_likely_(!!var->big_endian == !!(__BYTE_ORDER == __BIG_ENDIAN)) ? v : bswap_16(v);
}

static uint32_t dbus_variant_bswap32(DBusVariant *var, uint32_t v) {
        return _c_likely_(!!var->big_endian == !!(__BYTE_ORDER == __BIG_ENDIAN)) ? v : bswap_32(v);
}

static uint32_t dbus_variant_bswap64(DBusVariant *var, uint64_t v) {
        return _c_likely_(!!var->big_endian == !!(__BYTE_ORDER == __BIG_ENDIAN)) ? v : bswap_64(v);
}

static int dbus_variant_read_u8(DBusVariant *var, uint8_t *datap) {
        const void *p;
        int r;

        r = dbus_variant_read_data(var, 0, &p, sizeof(*datap));
        if (_c_likely_(r >= 0))
                *datap = *(const uint8_t *)p;

        return r;
}

static int dbus_variant_read_u16(DBusVariant *var, uint16_t *datap) {
        const void *p;
        int r;

        r = dbus_variant_read_data(var, 1, &p, sizeof(*datap));
        if (_c_likely_(r >= 0))
                *datap = dbus_variant_bswap16(var, *(const uint16_t *)p);

        return r;
}

static int dbus_variant_read_u32(DBusVariant *var, uint32_t *datap) {
        const void *p;
        int r;

        r = dbus_variant_read_data(var, 2, &p, sizeof(*datap));
        if (_c_likely_(r >= 0))
                *datap = dbus_variant_bswap32(var, *(const uint32_t *)p);

        return r;
}

static int dbus_variant_read_u64(DBusVariant *var, uint64_t *datap) {
        const void *p;
        int r;

        r = dbus_variant_read_data(var, 3, &p, sizeof(*datap));
        if (_c_likely_(r >= 0))
                *datap = dbus_variant_bswap64(var, *(const uint64_t *)p);

        return r;
}

static int dbus_variant_dummy_vread(DBusVariant *var, const char *format, va_list args) {
        void *p;
        char c;

        while ((c = *format++)) {
                switch (c) {
                case '[':
                case '(':
                case '{':
                case ']':
                case '>':
                case ')':
                case '}':
                        /* no @args required */
                        break;

                case '<':
                        p = va_arg(args, const char **);
                        if (p)
                                *(const char **)p = "()";
                        break;

                case 'y':
                        p = va_arg(args, uint8_t *);
                        if (p)
                                *(uint8_t *)p = 0;
                        break;

                case 'b':
                        p = va_arg(args, bool *);
                        if (p)
                                *(bool *)p = false;
                        break;

                case 'n':
                case 'q':
                        p = va_arg(args, uint16_t *);
                        if (p)
                                *(uint16_t *)p = 0;
                        break;

                case 'i':
                case 'h':
                case 'u':
                        p = va_arg(args, uint32_t *);
                        if (p)
                                *(uint32_t *)p = 0;
                        break;

                case 'x':
                case 't':
                        p = va_arg(args, uint64_t *);
                        if (p)
                                *(uint64_t *)p = 0;
                        break;

                case 'd':
                        p = va_arg(args, double *);
                        if (p)
                                *(double *)p = 0;
                        break;

                case 's':
                case 'g':
                        p = va_arg(args, const char **);
                        if (p)
                                *(const char **)p = "";
                        break;

                case 'o':
                        p = va_arg(args, const char **);
                        if (p)
                                *(const char **)p = "/";
                        break;

                case 'a':
                case 'v':
                default:
                        /*
                         * Invalid format-codes imply invalid @args, no way
                         * to recover meaningfully.
                         */
                        assert(0);
                        break;
                }
        }

        return -ENOTRECOVERABLE;
}

static int dbus_variant_try_vread(DBusVariant *var, const char *format, va_list args) {
        const char *str;
        uint64_t u64;
        uint32_t u32;
        uint16_t u16;
        uint8_t u8;
        void *p;
        char c;
        int r;

        /* error-path uses @format, so advance it late */
        for ( ; (c = *format); ++format) {
                r = dbus_variant_prepare_next(var, c);
                if (r < 0)
                        return r;

                /* XXX */
                switch (c) {
                case '[':
                        break;

                case '<':
                        break;

                case '(':
                        break;

                case '{':
                        break;

                case ']':
                        break;

                case '>':
                        break;

                case ')':
                        break;

                case '}':
                        break;

                case 'y':
                        r = dbus_variant_read_u8(var, &u8);
                        if (r < 0)
                                return r;

                        p = va_arg(args, uint8_t *);
                        if (p)
                                *(uint8_t *)p = u8;

                        break;

                case 'b':
                        r = dbus_variant_read_u32(var, &u32);
                        if (r < 0)
                                return r;
                        if (u32 != 0 && u32 != 1)
                                return -EBADMSG;

                        p = va_arg(args, bool *);
                        if (p)
                                *(bool *)p = u32;

                        break;

                case 'n':
                case 'q':
                        r = dbus_variant_read_u16(var, &u16);
                        if (r < 0)
                                return r;

                        p = va_arg(args, uint16_t *);
                        if (p)
                                *(uint16_t *)p = u16;

                        break;

                case 'i':
                case 'h':
                case 'u':
                        r = dbus_variant_read_u32(var, &u32);
                        if (r < 0)
                                return r;

                        p = va_arg(args, uint32_t *);
                        if (p)
                                *(uint32_t *)p = u32;

                        break;

                case 'x':
                case 't':
                case 'd':
                        r = dbus_variant_read_u64(var, &u64);
                        if (r < 0)
                                return r;

                        p = va_arg(args, uint64_t *);
                        if (p)
                                *(uint64_t *)p = u64;

                        break;

                case 's':
                case 'o':
                case 'g':
                        if (c == 'g') {
                                r = dbus_variant_read_u8(var, &u8);
                                if (r < 0)
                                        return r;

                                u32 = u8;
                        } else {
                                r = dbus_variant_read_u32(var, &u32);
                                if (r < 0)
                                        return r;
                        }

                        r = dbus_variant_read_data(var, 0, (const void **)&str, u32);
                        if (r < 0)
                                return r;

                        r = dbus_variant_read_u8(var, &u8);
                        if (r < 0)
                                return r;

                        if (u8 ||
                            strlen(str) != u32 ||
                            (c == 'o' && !dbus_variant_is_path(str)) ||
                            (c == 'g' && !dbus_variant_is_signature(str)))
                                return -EBADMSG;

                        p = va_arg(args, const char **);
                        if (p)
                                *(const char **)p = str;

                        break;

                default:
                        r = -ENOTRECOVERABLE;
                        goto error;
                }
        }

        return 0;

error:
        dbus_variant_dummy_vread(var, format, args);
        return r;
}

void dbus_variant_vread(DBusVariant *var, const char *format, va_list args) {
        if (var->poison)
                dbus_variant_dummy_vread(var, format, args);
        else if (!var->ro)
                var->poison = dbus_variant_dummy_vread(var, format, args);
        else
                var->poison = dbus_variant_try_vread(var, format, args);
}

static int dbus_variant_write_data(DBusVariant *var, int alignment, const void *data, size_t n_data) {
        size_t n, align;
        void *p;

        align = c_align_to(var->current->i_buffer, 1 << alignment) - var->current->i_buffer;

        if (_c_unlikely_(var->n_buffer - var->current->i_buffer < align + n_data)) {
                n = c_align_power2(var->current->i_buffer + align + n_data);
                n = c_max(n, 1 << DBUS_VARIANT_SIZE_INITIAL_SHIFT);

                if (n > (1 << DBUS_VARIANT_SIZE_MAX_SHIFT))
                        return -EMSGSIZE;

                p = realloc(var->buffer, n);
                if (!p)
                        return -ENOMEM;

                var->buffer = p;
                var->n_buffer = n;
        }

        memset(var->buffer + var->current->i_buffer, 0, align);
        if (data)
                memcpy(var->buffer + var->current->i_buffer + align, data, n_data);
        var->current->i_buffer += align + n_data;

        return 0;
}

static int dbus_variant_write_u8(DBusVariant *var, uint8_t v) {
        return dbus_variant_write_data(var, 0, &v, sizeof(v));
}

static int dbus_variant_write_u16(DBusVariant *var, uint16_t v) {
        return dbus_variant_write_data(var, 1, &v, sizeof(v));
}

static int dbus_variant_write_u32(DBusVariant *var, uint32_t v) {
        return dbus_variant_write_data(var, 2, &v, sizeof(v));
}

static int dbus_variant_write_u64(DBusVariant *var, uint64_t v) {
        return dbus_variant_write_data(var, 3, &v, sizeof(v));
}

static int dbus_variant_try_vwrite(DBusVariant *var, const char *format, va_list args) {
        const DBusVariantType *type;
        const char *str;
        uint64_t u64;
        uint32_t u32;
        uint16_t u16;
        uint8_t u8;
        double fp;
        size_t n;
        char c;
        int r;

        while ((c = *format++)) {
                /*
                 * First, verify the constraints. Meaning, we verify that the
                 * requested code is actually expected, and the operation is
                 * allowed (depth-check, container-check, ...).
                 */
                r = dbus_variant_prepare_next(var, c);
                if (r < 0)
                        return r;

                /*
                 * Now that the operation has passed validity checks, write the
                 * actual data.
                 */
                switch (c) {
                case '[':
                        /* write placeholder for array size */
                        r = dbus_variant_write_u32(var, 0);
                        if (r < 0)
                                return r;

                        /* all arrays contain alignment to enclosed type */
                        r = dbus_variant_write_data(var, 1 << (var->current->i_type + 1)->alignment, NULL, 0);
                        if (r < 0)
                                return r;

                        (var->current + 1)->i_buffer = var->current->i_buffer;
                        ++var->current;
                        continue; /* do not advance type iterator */

                case '<':
                        type = va_arg(args, const DBusVariantType *);

                        r = dbus_variant_write_u8(var, type->length);
                        if (r < 0)
                                return r;

                        r = dbus_variant_write_data(var, 0, NULL, type->length + 1);
                        if (r < 0)
                                return r;

                        for (n = 0; n < type->length; ++n)
                                var->buffer[var->current->i_buffer - type->length + n] = type[n].element;
                        var->buffer[var->current->i_buffer - 1] = 0;

                        (var->current + 1)->root_type = type;
                        (var->current + 1)->i_type = type;
                        (var->current + 1)->n_type = type->length;
                        (var->current + 1)->i_buffer = var->current->i_buffer;
                        ++var->current;
                        continue; /* do not advance type iterator */

                case '(':
                case '{':
                        /* align to 64-bit */
                        r = dbus_variant_write_data(var, 3, NULL, 0);
                        if (r < 0)
                                return r;

                        (var->current + 1)->i_buffer = var->current->i_buffer;
                        ++var->current;
                        continue; /* do not advance type iterator */

                case ']':
                        /* write previously written placeholder */
                        n = (var->current - 1)->i_buffer - 4;
                        assert(n == c_align_to(n, 4));
                        *(uint32_t *)&var->buffer[n] = var->current->i_buffer - n;

                        (var->current - 1)->i_buffer = var->current->i_buffer;
                        --var->current;
                        break;

                case '>':
                case ')':
                case '}':
                        (var->current - 1)->i_buffer = var->current->i_buffer;
                        --var->current;
                        break;

                case 'y':
                        u8 = va_arg(args, int);
                        r = dbus_variant_write_u8(var, u8);
                        if (r < 0)
                                return r;

                        break;

                case 'b':
                        u32 = va_arg(args, int);
                        r = dbus_variant_write_u32(var, !!u32);
                        if (r < 0)
                                return r;

                        break;

                case 'n':
                case 'q':
                        u16 = va_arg(args, int);
                        r = dbus_variant_write_u16(var, u16);
                        if (r < 0)
                                return r;

                        break;

                case 'i':
                case 'h':
                case 'u':
                        u32 = va_arg(args, uint32_t);
                        r = dbus_variant_write_u32(var, u32);
                        if (r < 0)
                                return r;

                        break;

                case 'x':
                case 't':
                        u64 = va_arg(args, uint64_t);
                        r = dbus_variant_write_u64(var, u64);
                        if (r < 0)
                                return r;

                        break;

                case 'd':
                        fp = va_arg(args, double);

                        static_assert(sizeof(double) == sizeof(uint64_t),
                                      "Unsupported size of 'double'");

                        r = dbus_variant_write_data(var, 3, &fp, sizeof(fp));
                        if (r < 0)
                                return r;

                        break;

                case 's':
                case 'o':
                        str = va_arg(args, const char *);
                        n = strlen(str);
                        if (_c_unlikely_(n > UINT32_MAX))
                                return -ENOTRECOVERABLE;

                        r = dbus_variant_write_u32(var, n);
                        if (r < 0)
                                return r;

                        r = dbus_variant_write_data(var, 0, str, n + 1);
                        if (r < 0)
                                return r;

                        break;

                case 'g':
                        str = va_arg(args, const char *);
                        n = strlen(str);
                        if (_c_unlikely_(n > UINT8_MAX))
                                return -ENOTRECOVERABLE;

                        r = dbus_variant_write_u8(var, n);
                        if (r < 0)
                                return r;

                        r = dbus_variant_write_data(var, 0, str, n + 1);
                        if (r < 0)
                                return r;

                        break;

                default:
                        return -ENOTRECOVERABLE;
                }

                /* advance type iterator, if necessary */
                if (var->current->container != 'a') {
                        var->current->i_type += var->current->i_type->length;
                        var->current->n_type -= var->current->i_type->length;
                }
        }

        return 0;
}

void dbus_variant_vwrite(DBusVariant *var, const char *format, va_list args) {
        if (!var->poison) {
                if (var->ro)
                        var->poison = -ENOTRECOVERABLE;
                else
                        var->poison = dbus_variant_try_vwrite(var, format, args);
        }
}
