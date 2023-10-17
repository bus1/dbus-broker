/*
 * File System Helpers
 */

#include <c-stdaux.h>
#include <dirent.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include "util/error.h"
#include "util/fs.h"
#include "util/string.h"

/**
 * fs_dirlist_new() - create new directory listing
 * @list:               output variable for new object
 * @n_allocated:        minimum number of slots to allocate initially
 *
 * Create a new directory listing with space for at least @n_allocated entries.
 * The new object is returned in @list on success.
 *
 * This might reserve space for more than @n_allocated entries, if deemed
 * necessary by the implementation.
 *
 * Return: 0 on success, negative error code on failure.
 */
int fs_dirlist_new(FsDirlist **listp, size_t n_allocated) {
        _c_cleanup_(fs_dirlist_freep) FsDirlist *list = NULL;

        if (n_allocated < 8)
                n_allocated = 8;

        list = calloc(1, sizeof(*list));
        if (!list)
                return error_origin(-ENOMEM);

        list->entries = calloc(n_allocated, sizeof(*list->entries));
        if (!list->entries)
                return error_origin(-ENOMEM);

        list->n_allocated = n_allocated;

        *listp = list;
        list = NULL;
        return 0;
}

/**
 * fs_dirlist_free() - release directory listing
 * @list:               list to operate on, or NULL
 *
 * Free the directory listing and all associated resources. If @list is NULL,
 * this is a no-op.
 *
 * Return: NULL is returned.
 */
FsDirlist *fs_dirlist_free(FsDirlist *list) {
        size_t i;

        if (list) {
                for (i = 0; i < list->n_entries; ++i)
                        c_free(list->entries[i]);
                c_free(list->entries);
                c_free(list);
        }

        return NULL;
}

/**
 * fs_dirlist_push() - push new entry to the end of the listing
 * @list:               list to operate on
 * @de:                 directory entry to push
 *
 * Push a copy of the directory entry given as @de to the end of the directory
 * listing @list. The entire directory entry is copied, no reference to @de is
 * retained.
 *
 * Return: 0 on success, negative error code on failure.
 */
int fs_dirlist_push(FsDirlist *list, const struct dirent *de) {
        struct dirent *next, **entries;
        size_t n, sz, n_name;

        /* Ensure the size is properly set with at least an empty name. */
        c_assert(de->d_reclen > offsetof(struct dirent, d_name));

        /* Ensure the record includes a terminating NULL in the name. */
        sz = de->d_reclen - offsetof(struct dirent, d_name);
        n_name = strnlen(de->d_name, sz);
        c_assert(n_name < sz);

        /* Increase array-size if minimum was exceeded. */
        if (list->n_entries >= list->n_allocated) {
                c_assert(list->n_allocated > 0);

                if (__builtin_mul_overflow(list->n_allocated, 2, &n))
                        return error_origin(-ENOMEM);
                if (__builtin_mul_overflow(n, sizeof(*list->entries), &sz))
                        return error_origin(-ENOMEM);

                entries = realloc(list->entries, sz);
                if (!entries)
                        return error_origin(-ENOMEM);

                list->entries = entries;
                list->n_allocated = n;
        }

        /* Copy the directory entry and store it. */

        sz = offsetof(struct dirent, d_name) + n_name + 1;
        next = malloc(sz);
        if (!next)
                return error_origin(-ENOMEM);

        memcpy(next, de, sz);
        list->entries[list->n_entries++] = next;

        return 0;
}

static int fs_dirlist_cmp_p(const void *va, const void *vb) {
        const struct dirent * const *pa = va, * const *pb = vb;
        return strcmp((*pa)->d_name, (*pb)->d_name);
}

/**
 * fs_dirlist_sort() - sort all entries alphabetically
 * @list:               list to operate on
 *
 * Sort all entries of the given directory listing alphabetically, based on
 * their entry name.
 *
 * Note that a listing of a directory can never contain two entries with equal
 * names. However, if such a listing was manually crafted, their order is
 * preserved.
 */
void fs_dirlist_sort(FsDirlist *list) {
        qsort(
                list->entries,
                list->n_entries,
                sizeof(*list->entries),
                fs_dirlist_cmp_p
        );
}

/**
 * fs_dir_list() - enumerate all entries of a directory
 * @dir:                directory to operate on
 * @listp:              output variable for the directory listing
 * @flags:              flags for the operation
 *
 * Read all entries of an open directory descriptor and collect them in a
 * directory listing. The directory listing is returned in @listp on success
 * and it is the responsibility of the caller to release it via
 * `fs_dirlist_free()` when done.
 *
 * The directory entries are always sorted via `fs_dirlist_sort()` before they
 * are returned. Hence, the semi-random on-disk order of directory entries is
 * not exposed to the caller.
 *
 * Return: 0 on success, negative error code on failure.
 */
int fs_dir_list(DIR *dir, FsDirlist **listp, unsigned int flags) {
        _c_cleanup_(fs_dirlist_freep) FsDirlist *list = NULL;
        struct dirent *de;
        int r;

        r = fs_dirlist_new(&list, 0);
        if (r)
                return error_fold(r);

        for (
                errno = 0, de = readdir(dir);
                de;
                errno = 0, de = readdir(dir)
        ) {
                if (string_equal(de->d_name, "."))
                        continue;
                if (string_equal(de->d_name, ".."))
                        continue;
                if ((flags & FS_DIR_FLAG_NO_HIDDEN) && de->d_name[0] == '.')
                        continue;

                r = fs_dirlist_push(list, de);
                if (r)
                        return error_fold(r);
        }
        if (errno > 0)
                return error_origin(-errno);

        /*
         * The order returned by the kernel is based on the order on disk,
         * which is effectively random. Preserving the on-disk order is useful
         * when operating on streamed data, since it avoids collecting the
         * entire listing. However, here we explicitly want to collect the
         * entire listing, hence we always want to sort the entries to prevent
         * accidentally relying on the semi-random on-disk order.
         */
        fs_dirlist_sort(list);

        *listp = list;
        list = NULL;
        return 0;
}
