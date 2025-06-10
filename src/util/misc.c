/*
 * Miscellaneous Helpers
 *
 * These are helpers that have no other obvious home.
 */

#include <c-stdaux.h>
#include <fcntl.h>
#include <grp.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include "util/error.h"
#include "util/misc.h"
#include "util/syscall.h"

#ifdef F_LINUX_SPECIFIC_BASE
#  define MISC_F_ADD_SEALS (F_LINUX_SPECIFIC_BASE + 9)
#  define MISC_F_GET_SEALS (F_LINUX_SPECIFIC_BASE + 10)
#else
#  define MISC_F_ADD_SEALS (1024 + 9)
#  define MISC_F_GET_SEALS (1024 + 10)
#endif

/**
 * misc_memfd() - create non-executable memfd
 * @name:       name for memfd inode
 * @uflags:     memfd flags
 * @useals:     initial seals
 *
 * This is a convenience wrapper around `memfd_create(2)`. It creates a memfd
 * and returns it. However, a set of additional rules apply:
 *
 *  * The caller must specify either `MFD_EXEC` or `MFD_NOEXEC_SEAL`. This
 *    is enforced. If the kernel does not support the flags, this will strip
 *    them and manually edit the executable bit on the inode. Unfortunately,
 *    `F_SEAL_EXEC` will then not be available. If required, you must set it
 *    explicitly in @seals to ensure the call fails on older kernels. You
 *    likely then also want `F_SEAL_SEAL` and `MFD_ALLOW_SEALING`, though.
 *
 *    IOW, if you require `F_SEAL_EXEC`, you likely need:
 *
 *        misc_memfd(
 *              "...",
 *              MISC_MFD_ALLOW_SEALING | MISC_MFD_NOEXEC_SEAL,
 *              MISC_F_SEAL_EXEC
 *        );
 *
 *    Throw in `MFD_CLOEXEC` or `F_SEAL_SEAL` as required.
 *
 *  * If `MFD_NOEXEC_SEAL` is used without `MFD_ALLOW_SEALING`, sealing will
 *    be disabled (even though some kernel versions implicitly enable it).
 *
 *  * An initial set of seals is applied to the memfd, if specified in
 *    @seals. Note that this is not allowed if sealing was not enabled.
 *
 * Return: New memfd file-descriptor on success, -1 on failure.
 */
int misc_memfd(const char *name, unsigned int uflags, unsigned int useals) {
        _c_cleanup_(c_closep) int fd = -1;
        unsigned int flags = uflags;
        unsigned int seals = useals;
        unsigned int kseals;
        struct stat st;
        int r;

        /*
         * You cannot set any seals if you disable sealing (apart from
         * F_SEAL_SEAL, which is what the kernel sets to disable sealing).
         */
        if (!(flags & MISC_MFD_ALLOW_SEALING)) {
                if (seals & ~MISC_F_SEAL_SEAL)
                        return error_origin(-ENOTRECOVERABLE);

                /* Already set by the kernel if sealing is disabled. */
                seals &= ~MISC_F_SEAL_SEAL;
        }

        /*
         * Newer kernels require you to either specify `MFD_EXEC` or
         * `MFD_NOEXEC_SEAL` or it will warn loudly. Hence we enforce this in
         * our codebase. For older kernels, we strip these flags automatically.
         */
        if (!(flags & (MISC_MFD_EXEC | MISC_MFD_NOEXEC_SEAL)))
                return error_origin(-ENOTRECOVERABLE);

        /*
         * Create the memfd. If the flags are not supported, strip the EXEC
         * flags and try again. We can emulate them, and older kernels refuse
         * them.
         */
        fd = syscall_memfd_create(name, flags);
        if (fd < 0 && errno == EINVAL) {
                flags &= ~(MISC_MFD_EXEC | MISC_MFD_NOEXEC_SEAL);
                fd = syscall_memfd_create(name, flags);
        }
        if (fd < 0)
                return error_origin(-errno);

        /*
         * If the kernel did not support `MFD_NOEXEC_SEAL`, but we want it, we
         * strip the executable bits ourselves. They are set by default.
         */
        if ((uflags & MISC_MFD_NOEXEC_SEAL) && !(flags & MISC_MFD_NOEXEC_SEAL)) {
                r = fstat(fd, &st);
                if (r < 0)
                        return error_origin(-errno);

                r = fchmod(fd, st.st_mode & 07666);
                if (r < 0)
                        return error_origin(-errno);
        }

        /*
         * If we ended up passing `MFG_NOEXEC_SEAL` to the kernel, some kernel
         * versions will implicitly enable sealing. This is very unfortunate,
         * so we revert this if the caller did not explicitly allow it. To
         * disable sealing, simply set `F_SEAL_SEAL`, which is also what the
         * kernel does.
         */
        if ((flags & MISC_MFD_NOEXEC_SEAL) && !(flags & MISC_MFD_ALLOW_SEALING))
                seals |= MISC_F_SEAL_SEAL;

        /*
         * If the user wants initial seals, lets set them. Sadly,
         * memfd_create(2) does not support initial seals, so we have to call
         * into the kernel again.
         */
        if (seals) {
                r = misc_memfd_get_seals(fd, &kseals);
                if (r)
                        return error_fold(r);

                if (seals & ~kseals) {
                        r = misc_memfd_add_seals(fd, seals);
                        if (r)
                                return error_fold(r);
                }
        }

        r = fd;
        fd = -1;
        return r;
}

/**
 * misc_memfd_add_seals() - add seals to a memfd
 * @fd:         memfd to operate on
 * @seals:      seals to set
 *
 * Add the specified seals to the set of seals on the memfd. If the FD does not
 * refer to a memfd (or other file that supports sealing), an error will be
 * returned. If the memfd does not support sealing, or if `F_SEAL_SEAL` was
 * already set, `-EPERM` is returned.
 *
 * Write access is needed to add seals to a memfd, or `-EPERM` will be
 * returned.
 *
 * Adding seals that are already set is a no-op (unless `F_SEAL_SEAL` is set,
 * in which case this operation always fails).
 *
 * Return: 0 on success, negative error code on failure.
 */
int misc_memfd_add_seals(int fd, unsigned int seals) {
        int r;

        r = fcntl(fd, MISC_F_ADD_SEALS, seals);
        if (r < 0)
                return error_origin(-errno);

        return 0;
}

/**
 * misc_memfd_get_seals() - query seals of a memfd
 * @fd:         memfd to operate on
 * @sealsp:     output argument to store retrieved seals
 *
 * Query the seals of the memfd. If the FD does not refer to a memfd (or other
 * file that supports sealing), an error will be returned.
 *
 * On success, the seals are written to @sealsp.
 *
 * Return: 0 on success, negative error code on failure.
 */
int misc_memfd_get_seals(int fd, unsigned int *sealsp) {
        int seals;

        seals = fcntl(fd, MISC_F_GET_SEALS);
        if (seals < 0)
                return error_origin(-errno);

        *sealsp = seals;
        return 0;
}

/**
 * util_umul64_saturating() - saturating multiplication
 * @a:                  first operand
 * @b:                  second operand
 *
 * This calculates @a multiplied by @b and returns the result. In case of an
 * integer overflow, it will return `UINT64_MAX`.
 *
 * Return: The saturated result is returned.
 */
uint64_t util_umul64_saturating(uint64_t a, uint64_t b) {
        uint64_t res;

        if (__builtin_mul_overflow(a, b, &res))
                res = UINT64_MAX;

        return res;
}

/**
 * util_z2u_saturating() - saturating cast of size_t to unsigned int
 * @v:                  value to cast
 *
 * This will cast a value of `size_t` to `unsigned int`, saturating the
 * value at `UINT_MAX` in case of overflow.
 *
 * Return: The casted, saturated value is returned.
 */
unsigned int util_z2u_saturating(size_t v) {
        unsigned int cast;

        cast = (unsigned int)v;
        if ((size_t)cast != v)
                return UINT_MAX;
        else
                return cast;
}

/**
 * util_t2u_saturating() - saturating cast of uint64_t to unsigned int
 * @v:                  value to cast
 *
 * This will cast a value of `uint64_t` to `unsigned int`, saturating the
 * value at `UINT_MAX` in case of overflow.
 *
 * Return: The casted, saturated value is returned.
 */
unsigned int util_t2u_saturating(uint64_t v) {
        unsigned int cast;

        cast = (unsigned int)v;
        if ((uint64_t)cast != v)
                return UINT_MAX;
        else
                return cast;
}

int util_drop_permissions(uint32_t uid, uint32_t gid) {
        int r;

        /* for compatibility to dbus-daemon, this must be non-fatal */
        setgroups(0, NULL);

        r = setgid(gid);
        if (r < 0)
                return error_origin(-errno);

        r = setuid(uid);
        if (r < 0)
                return error_origin(-errno);

        return 0;
}

void util_peak_update(size_t *peak, size_t update) {
        if (update > *peak)
                *peak = update;
}
