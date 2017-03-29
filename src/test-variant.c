/*
 * Test D-Bus Variants
 */

#include <c-macro.h>
#include <stdlib.h>
#include "dbus-variant.h"

static const char test_array_signature[] = {
        "u"
        "(nq)"
        "a{sa(vt)}"
};

static const DBusVariantType test_array[] = {
        /* "u" */
        {
                .size = 4,
                .alignment = 2,
                .element = 'u',
                .length = 1,
                .basic = 1,
        },
        /* "(nq)" */
        {
                .size = 4,
                .alignment = 3,
                .element = '(',
                .length = 4,
                .basic = 0,
        },
        {
                .size = 2,
                .alignment = 1,
                .element = 'n',
                .length = 1,
                .basic = 1,
        },
        {
                .size = 2,
                .alignment = 1,
                .element = 'q',
                .length = 1,
                .basic = 1,
        },
        {
                .size = 0,
                .alignment = 0,
                .element = ')',
                .length = 1,
                .basic = 0,
        },
        /* "a{sa(vt)}" */
        {
                .size = 0,
                .alignment = 2,
                .element = 'a',
                .length = 9,
                .basic = 0,
        },
        {
                .size = 0,
                .alignment = 3,
                .element = '{',
                .length = 8,
                .basic = 0,
        },
        {
                .size = 0,
                .alignment = 2,
                .element = 's',
                .length = 1,
                .basic = 1,
        },
        {
                .size = 0,
                .alignment = 2,
                .element = 'a',
                .length = 5,
                .basic = 0,
        },
        {
                .size = 0,
                .alignment = 3,
                .element = '(',
                .length = 4,
                .basic = 0,
        },
        {
                .size = 0,
                .alignment = 0,
                .element = 'v',
                .length = 1,
                .basic = 0,
        },
        {
                .size = 8,
                .alignment = 3,
                .element = 't',
                .length = 1,
                .basic = 1,
        },
        {
                .size = 0,
                .alignment = 0,
                .element = ')',
                .length = 1,
                .basic = 0,
        },
        {
                .size = 0,
                .alignment = 0,
                .element = '}',
                .length = 1,
                .basic = 0,
        },
};

static void test_type_tokenizer(void) {
        _c_cleanup_(c_freep) DBusVariantType *type = NULL;
        const DBusVariantType *expect;
        const char *signature;
        size_t i, n_signature;
        long n;

        /*
         * This runs dbus_variant_type_new_from_signature() across
         * @test_array_signature until its end. It verifies the output is the
         * exact sequence provided by @test_array.
         */

        signature = test_array_signature;
        n_signature = strlen(signature);
        expect = test_array;

        do {
                n = dbus_variant_type_new_from_signature(&type, signature, n_signature);
                assert(n_signature || n < 0);
                assert(!n_signature || n > 0);

                if (n >= 0) {
                        assert(n == expect->length);

                        for (i = 0; i < n; ++i) {
                                assert(expect[i].size == type[i].size);
                                assert(expect[i].alignment == type[i].alignment);
                                assert(expect[i].element == type[i].element);
                                assert(expect[i].length == type[i].length);
                                assert(expect[i].basic == type[i].basic);
                        }

                        n_signature -= n;
                        signature += n;
                        expect += n;
                        type = c_free(type);
                }
        } while (n_signature);

        assert(expect == test_array + C_ARRAY_SIZE(test_array));
}

int main(int argc, char **argv) {
        test_type_tokenizer();
        return 0;
}
