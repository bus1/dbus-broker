/*
 * Test miscellaneous helpers
 */

#undef NDEBUG
#include <c-stdaux.h>
#include <stdlib.h>
#include "util/misc.h"

static void test_umul_saturating(void) {
        static const struct {
                uint64_t input_a;
                uint64_t input_b;
                uint64_t output;
        } values[] = {
                { 0, 0, 0 },
                { 0, 1, 0 },
                { 1, 0, 0 },
                { 1, 1, 1 },

                { UINT32_MAX, UINT32_MAX, UINT64_MAX - UINT64_C(2) * UINT32_MAX },
                { UINT32_MAX, UINT32_MAX + UINT64_C(1), UINT64_MAX - UINT32_MAX },
                { UINT32_MAX + UINT64_C(1), UINT32_MAX + UINT64_C(1), UINT64_MAX },

                { 1, UINT64_MAX - 1, UINT64_MAX - 1 },
                { UINT64_MAX - 1, 1, UINT64_MAX - 1 },
                { UINT64_MAX - 1, 2, UINT64_MAX },
        };
        uint64_t output;
        size_t i;

        for (i = 0; i < C_ARRAY_SIZE(values); ++i) {
                output = util_umul64_saturating(values[i].input_a, values[i].input_b);
                c_assert(output == values[i].output);
        }
}

int main(int argc, char **argv) {
        test_umul_saturating();
        return 0;
}
