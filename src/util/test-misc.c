/*
 * Test miscellaneous helpers
 */

#undef NDEBUG
#include <c-stdaux.h>
#include <stdlib.h>
#include <sys/stat.h>
#include "util/misc.h"

/*
 * Check for which memfd-seals are supported by the running kernel and return
 * them as mask to the caller. This allows running tests on older kernels,
 * that possibly do not support the newer seals.
 */
static unsigned int memfd_seals(void) {
        unsigned int seal_mask;
        int fd;

        seal_mask = MISC_F_SEAL_SEAL | MISC_F_SEAL_SHRINK |
                    MISC_F_SEAL_GROW | MISC_F_SEAL_WRITE;

        fd = misc_memfd(
                "test",
                MISC_MFD_ALLOW_SEALING | MISC_MFD_NOEXEC_SEAL,
                MISC_F_SEAL_FUTURE_WRITE
        );
        if (fd >= 0) {
                seal_mask |= MISC_F_SEAL_FUTURE_WRITE;
                c_close(fd);
        }

        fd = misc_memfd(
                "test",
                MISC_MFD_ALLOW_SEALING | MISC_MFD_NOEXEC_SEAL,
                MISC_F_SEAL_EXEC
        );
        if (fd >= 0) {
                seal_mask |= MISC_F_SEAL_EXEC;
                c_close(fd);
        }

        return seal_mask;
}

static void test_memfd(void) {
        static const struct {
                unsigned int in_flags;
                unsigned int in_seals;
                int out_error;
                unsigned int out_seals;
                unsigned int out_fmode;
        } v[] = {
                {
                        .out_error = -ENOTRECOVERABLE,
                },
                {
                        .in_flags = MISC_MFD_EXEC,
                        .in_seals = MISC_F_SEAL_WRITE,
                        .out_error = -ENOTRECOVERABLE,
                },
                {
                        .in_flags = MISC_MFD_EXEC,
                        .out_seals = MISC_F_SEAL_SEAL,
                        .out_fmode = 0777,
                },
                {
                        .in_flags = MISC_MFD_EXEC,
                        .in_seals = MISC_F_SEAL_SEAL,
                        .out_seals = MISC_F_SEAL_SEAL,
                        .out_fmode = 0777,
                },
                {
                        .in_flags = MISC_MFD_NOEXEC_SEAL,
                        .out_seals = MISC_F_SEAL_SEAL | MISC_F_SEAL_EXEC,
                        .out_fmode = 0666,
                },
                {
                        .in_flags = MISC_MFD_ALLOW_SEALING | MISC_MFD_NOEXEC_SEAL,
                        .out_seals = MISC_F_SEAL_EXEC,
                        .out_fmode = 0666,
                },
                {
                        .in_flags = MISC_MFD_ALLOW_SEALING | MISC_MFD_NOEXEC_SEAL,
                        .in_seals = MISC_F_SEAL_WRITE,
                        .out_seals = MISC_F_SEAL_WRITE | MISC_F_SEAL_EXEC,
                        .out_fmode = 0666,
                },
        };
        unsigned int seals, seal_mask;
        struct stat st;
        size_t i;
        int r, fd;

        seal_mask = memfd_seals();

        for (i = 0; i < C_ARRAY_SIZE(v); ++i) {
                c_assert(!(v[i].in_seals & ~seal_mask));

                fd = misc_memfd("test", v[i].in_flags, v[i].in_seals);
                if (fd < 0) {
                        c_assert(fd == v[i].out_error);
                        continue;
                }
                c_assert(!v[i].out_error);

                r = misc_memfd_get_seals(fd, &seals);
                c_assert(r >= 0);
                c_assert((seals & seal_mask) == (v[i].out_seals & seal_mask));

                r = fstat(fd, &st);
                c_assert(r >= 0);
                c_assert((st.st_mode & 07777) == v[i].out_fmode);

                c_close(fd);
        }
}

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

static void test_casts(void) {
        static const struct {
                size_t from;
                unsigned int to;
        } casts_z2u_sat[] = {
                { 0, 0 },
                { 32, 32 },
                { 256, 256 },
                { SIZE_MAX, UINT_MAX },
#if SIZE_MAX > UINT_MAX
                { (size_t)UINT_MAX, UINT_MAX },
                { (size_t)UINT_MAX + 1, UINT_MAX },
                { (size_t)UINT_MAX * 2, UINT_MAX },
#endif
        };
        static const struct {
                uint64_t from;
                unsigned int to;
        } casts_t2u_sat[] = {
                { 0, 0 },
                { 32, 32 },
                { 256, 256 },
                { (uint64_t)UINT_MAX, UINT_MAX },
                { (uint64_t)UINT_MAX + 1, UINT_MAX },
                { (uint64_t)UINT_MAX * 2, UINT_MAX },
                { UINT64_MAX, UINT_MAX },
        };
        size_t i;

        for (i = 0; i < C_ARRAY_SIZE(casts_z2u_sat); ++i) {
                unsigned int r;

                r = util_z2u_saturating(casts_z2u_sat[i].from);
                c_assert(r == casts_z2u_sat[i].to);
        }

        for (i = 0; i < C_ARRAY_SIZE(casts_t2u_sat); ++i) {
                unsigned int r;

                r = util_t2u_saturating(casts_t2u_sat[i].from);
                c_assert(r == casts_t2u_sat[i].to);
        }
}

static void test_vfreep(void) {
        char **v;

        /* No-op on NULL. */
        v = NULL;
        misc_vfreep(&v);

        /* Single free(*v) for empty array. */
        v = calloc(1, sizeof(*v));
        c_assert(v);
        misc_vfreep(&v);

        /* Full iterated release for filled array, stopping at NULL. */
        v = calloc(4, sizeof(*v));
        c_assert(v);
        v[0] = strdup("foo");
        v[1] = strdup("bar");
        v[2] = NULL;
        v[3] = (void *)0x1; /* garbage after NULL must be ignored */
        c_assert(v[0] && v[1]);
        misc_vfreep(&v);
}

int main(int argc, char **argv) {
        test_memfd();
        test_umul_saturating();
        test_casts();
        test_vfreep();
        return 0;
}
