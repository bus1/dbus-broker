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
int misc_memfd_get_seals(int fd);

uint64_t util_umul64_saturating(uint64_t a, uint64_t b);
int util_drop_permissions(uint32_t uid, uint32_t gid);
