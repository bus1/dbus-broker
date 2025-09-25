#pragma once

/*
 * Miscellaneous Helpers
 */

#include <c-stdaux.h>
#include <stdlib.h>

#define MISC_MFD_CLOEXEC                0x0001U
#define MISC_MFD_ALLOW_SEALING          0x0002U
#define MISC_MFD_HUGETLB                0x0004U
#define MISC_MFD_NOEXEC_SEAL            0x0008U
#define MISC_MFD_EXEC                   0x0010U

#define MISC_F_SEAL_SEAL                0x0001U
#define MISC_F_SEAL_SHRINK              0x0002U
#define MISC_F_SEAL_GROW                0x0004U
#define MISC_F_SEAL_WRITE               0x0008U
#define MISC_F_SEAL_FUTURE_WRITE        0x0010U
#define MISC_F_SEAL_EXEC                0x0020U

int misc_memfd(const char *name, unsigned int uflags, unsigned int useals);
int misc_memfd_add_seals(int fd, unsigned int seals);
int misc_memfd_get_seals(int fd, unsigned int *sealsp);

uint64_t util_umul64_saturating(uint64_t a, uint64_t b);
unsigned int util_z2u_saturating(size_t v);
unsigned int util_t2u_saturating(uint64_t v);
int util_drop_permissions(uint32_t uid, uint32_t gid);

void util_peak_update(size_t *peak, size_t update);

/**
 * misc_vfreep() - Cleanup helper for NULL-terminated arrays of allocations
 * v:           Pointer to the array of allocated objects (i.e., `void ***p`)
 *
 * This interprets `v` as `void ***`, assuming it points to an array of
 * allocated objects. `v` must not be NULL.
 *
 * If `*v` is NULL, this is a no-op. Otherwise, `*v` is iterated as array of
 * pointers, terminated by a NULL entry. All entries are passed to free(), with
 * a final call to `*v` itself.
 */
static inline void misc_vfreep(void *v) {
        void ***p = v;
        size_t i;

        if (*p) {
                for (i = 0; (*p)[i]; ++i)
                        free((*p)[i]);
                free(*p);
        }
}
