/*
 * Proc Helpers
 */

#include <c-stdaux.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include "util/error.h"
#include "util/proc.h"
#include "util/string.h"

/*
 * A file in /proc can be at most 4M minus one. If required, we start with a 4K
 * read, then try a 4M one if that fails. In the vast majority of cases, 4K
 * will be enough.
 */
#define PROC_SIZE_MIN (4U*1024U)
#define PROC_SIZE_MAX (4U*1024U*1024U - 1U)

/**
 * proc_field() - Extract individual field from proc-text-file
 * @data:       content of the file
 * @key:        key to find
 * @valuep:     output variable to store the duplicated value
 *
 * Search through a key-value proc-file for the specified key and return the
 * value as newly allocated string.
 *
 * The caller is responsible to free the value via `free()`.
 *
 * The proc-file must be a standard text-file with no embedded string
 * terminators. It is the caller's responsibility to use this only on
 * suitable files.
 *
 * Return: 0 on success, PROC_E_NOT_FOUND if the key was not found, and
 *         negative error code on failure.
 */
int proc_field(const char *data, const char *key, char **valuep) {
        const size_t n_key = strlen(key);
        const char *pos, *t;
        char *value;

        pos = data;
        do {
                do {
                        /* Find next occurrence of they key. */
                        t = strstr(pos, key);
                        if (!t)
                                return PROC_E_NOT_FOUND;

                        pos = t + n_key;

                        /* Continue if the key does not start a line. */
                } while (t != data && t[-1] != '\n');

                /* Skip possible whitespace before the colon. */
                pos += strspn(pos, " \t");

                /* Continue if the key is not complete. */
        } while (*pos != ':');

        /* Skip over the colon and whitespace. */
        ++pos;
        pos += strspn(pos, " \t");

        /* Extract the value. */
        value = strndup(pos, strcspn(pos, " \t\n\r"));
        if (!value)
                return error_origin(-ENOMEM);

        *valuep = value;
        return 0;
}

/**
 * proc_read() - Read a proc-file into memory
 * @fd:         file-descriptor to a file in procfs
 * @datap:      output variable for the read data
 * @n_datap:    output variable for the length of the data blob
 *
 * Read the entire proc-fs file given as @fd into memory and return it to the
 * caller. This will always read from file position 0 regardless of the current
 * file position.
 *
 * The resulting data block is always terminated by a binary zero. This allows
 * string operations on the data blob without any length checks. @n_datap will
 * not include this sentinal zero, unless it was actually part of the file.
 *
 * Note that standard procfs files cannot exceed 4M-1 in size, and their API
 * implementation actually limits it to 4M-2.
 *
 * If the proc-fs file in question does not follow the standard proc-fs rules,
 * the caller should be aware of the limitations of this function.
 *
 * It is the responsibility of the caller to free the data via `free()`.
 *
 * Return: 0 on success, negative error code on failure.
 */
int proc_read(int fd, char **datap, size_t *n_datap) {
        _c_cleanup_(c_freep) char *data = NULL;
        ssize_t l;

        data = malloc(PROC_SIZE_MIN);
        if (!data)
                return error_origin(-ENOMEM);

        l = pread(fd, data, PROC_SIZE_MIN, 0);
        if (l < 0)
                return error_origin(-errno);

        /*
         * Proc never returns short reads unless end-of-file was reached. Thus,
         * a short read implies end-of-file. Furthermore, in case the proc file
         * is backed by a direct driver read, it might always return fresh data
         * on each read, as if we used `pread(..., 0)`. Hence, we rely on short
         * reads to know how long the file was.
         *
         * Lastly, note that we cannot ever attempt a read longer than
         * PROC_SIZE_MAX, since it would be immediately refused by the kernel.
         * So the longest successful read we can return to the caller is
         * actually `PROC_SIZE_MAX - 1`, otherwise we wouldn't know whether it
         * was complete.
         */
        if (l >= (ssize_t)PROC_SIZE_MIN) {
                data = c_free(data);
                data = malloc(PROC_SIZE_MAX);
                if (!data)
                        return error_origin(-ENOMEM);

                l = pread(fd, data, PROC_SIZE_MAX, 0);
                if (l < 0)
                        return error_origin(-errno);
                if (l >= (ssize_t)PROC_SIZE_MAX)
                        return error_origin(-E2BIG);
        }

        /* Ensure a terminating 0 to allow direct searches of text-files. */
        data[l] = 0;

        if (datap) {
                *datap = data;
                data = NULL;
        }
        if (n_datap)
                *n_datap = (size_t)l;
        return 0;
}

int proc_get_seclabel(pid_t pid, char **labelp, size_t *n_labelp) {
        _c_cleanup_(c_fclosep) FILE *f = NULL;
        char path[64], buffer[LINE_MAX] = {}, *c, *label;

        if (pid == PROC_PID_SELF)
                strcpy(path, "/proc/self/attr/current");
        else if (pid > 0)
                sprintf(path, "/proc/%"PRIu32"/attr/current", (uint32_t)pid);
        else
                return error_origin(-EINVAL);

        f = fopen(path, "re");
        if (f) {
                errno = 0;
                if (!fgets(buffer, sizeof(buffer), f)) {
                        /*
                         * If LSM core code is enabled, but no LSM is loaded,
                         * the kernel returns EINVAL. In that case, we treat
                         * the seclabel as empty string, similar to how the
                         * user-space LSM libraries do.
                         */
                        if (ferror(f) && errno != EINVAL)
                                return errno ? error_origin(-errno) : error_origin(-ENOTRECOVERABLE);
                }
        } else if (errno != ENOENT) {
                return error_origin(-errno);
        }

        c = strchrnul(buffer, '\n');
        label = strndup(buffer, c - buffer);
        if (!label)
                return error_origin(-ENOMEM);

        if (n_labelp)
                *n_labelp = strlen(label);
        *labelp = label;
        return 0;
}

int proc_resolve_pidfd(int pidfd, pid_t *pidp) {
        _c_cleanup_(c_freep) char *data = NULL, *field = NULL;
        _c_cleanup_(c_closep) int fd = -1;
        char path[64];
        int r;

        sprintf(path, "/proc/self/fdinfo/%d", pidfd);
        fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0)
                return error_origin(-errno);

        r = proc_read(fd, &data, NULL);
        if (r)
                return error_fold(r);

        r = proc_field(data, "Pid", &field);
        if (r)
                return error_fold(r);

        r = util_strtoint(pidp, field);
        if (r)
                return error_fold(r);

        return 0;
}
