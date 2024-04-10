/*
 * File-Descriptor List
 *
 * The FDList object is a small wrapper around a fixed-size array of
 * file-descriptors. It allows easy handling of file-descriptor sets as atomic
 * entity, while still providing access to individual entries.
 *
 * Furthermore, the FDList object is meant as supplement for AF_UNIX sockets.
 * Hence, it stores FDs as a cmsghdr entry, ready to be used with sendmsg(2).
 */

#include <c-stdaux.h>
#include <stdlib.h>
#include <sys/socket.h>
#include "util/error.h"
#include "util/fdlist.h"

/**
 * fdlist_new_with_fds() - create fdlist with a set of FDs
 * @listp:              output for new fdlist
 * @fds:                FD array to import
 * @n_fds:              array size of @fds
 *
 * This creates a new fdlist and imports the FDs given as @fds + @n_fds. The
 * FDs are still owned by the caller and will not be freed on fdlist_free().
 *
 * Return: 0 on success, negative error code on failure.
 */
int fdlist_new_with_fds(FDList **listp, const int *fds, size_t n_fds) {
        FDList *list;

        list = malloc(sizeof(*list) + CMSG_SPACE(n_fds * sizeof(int)));
        if (!list)
                return error_origin(-ENOMEM);

        list->consumed = false;
        list->cmsg->cmsg_len = CMSG_LEN(n_fds * sizeof(int));
        list->cmsg->cmsg_level = SOL_SOCKET;
        list->cmsg->cmsg_type = SCM_RIGHTS;
        c_memcpy(fdlist_data(list), fds, n_fds * sizeof(int));

        *listp = list;
        return 0;
}

/**
 * fdlist_new_consume_fds() - create fdlist and consume FDs
 * @listp:              output for new fdlist
 * @fds:                FD array to import
 * @n_fds:              array size of @fds
 *
 * This is the same as fdlist_new_with_fds() but consumes the FDs. That is, the
 * caller no longer owns the FDs, and the FDs will be closed on fdlist_free().
 *
 * Return: 0 on success, negative error code on failure.
 */
int fdlist_new_consume_fds(FDList **listp, const int *fds, size_t n_fds) {
        int r;

        r = fdlist_new_with_fds(listp, fds, n_fds);
        if (!r)
                (*listp)->consumed = true;

        return r;
}

/**
 * fdlist_new_dup_fds() - create fdlist and duplicate FDs
 * @listp:              output for new fdlist
 * @fds:                FD array to duplicate
 * @n_fds:              array size of @fds
 *
 * This is the same as fdlist_new_with_fds() but duplicates the FDs. That is,
 * the caller retains the FDs, and an independent copy of each FD will be owned
 * by the new object.
 *
 * Return: 0 on success, negative error code on failure.
 */
int fdlist_new_dup_fds(FDList **listp, const int *fds, size_t n_fds) {
        _c_cleanup_(fdlist_freep) FDList *list = NULL;
        size_t i;
        int r, *p;

        r = fdlist_new_with_fds(&list, fds, n_fds);
        if (r)
                return error_trace(r);

        p = fdlist_data(list);
        for (i = 0; i < n_fds; ++i) {
                p[i] = fcntl(p[i], F_DUPFD_CLOEXEC, 3);
                if (p[i] < 0) {
                        r = -errno;
                        while (i > 0) {
                                --i;
                                p[i] = c_close(p[i]);
                        }
                        return error_origin(r);
                }
        }

        list->consumed = true;

        *listp = list;
        list = NULL;
        return 0;
}

/**
 * fdlist_free() - free fdlist
 * @list:               fdlist to operate on, or NULL
 *
 * This frees the fdlist given as @list. If the file-descriptors were marked as
 * `consumed`, this function will close them. Otherwise, they're left
 * untouched.
 *
 * If @list is NULL, this is a no-op.
 *
 * Return: NULL is returned.
 */
FDList *fdlist_free(FDList *list) {
        size_t i, n;
        int *p;

        if (list) {
                p = fdlist_data(list);
                n = fdlist_count(list);

                if (list->consumed)
                        for (i = 0; i < n; ++i)
                                c_close(p[i]);

                free(list);
        }

        return NULL;
}

/**
 * fdlist_truncate() - truncate fdlist
 * @list:               fdlist to operate on
 * @n_fds:              number of FDs to retain
 *
 * This shrinks the fdlist to size @n_fds. The caller must make sure the fdlist
 * is sized greater than, or equal to, @n_fds.
 *
 * If the discarded FDs were marked as consumed, then this will close them.
 * Otherwise, they're left untouched.
 */
void fdlist_truncate(FDList *list, size_t n_fds) {
        size_t i, n;
        int *p;

        p = fdlist_data(list);
        n = fdlist_count(list);

        c_assert(n_fds <= n);

        if (list->consumed)
                for (i = n_fds; i < n; ++i)
                        c_close(p[i]);

        list->cmsg->cmsg_len = CMSG_LEN(n_fds * sizeof(int));
}

/**
 * fdlist_steal() - steal FD
 * @list:               fdlist to operate on
 * @index:              index of FD
 *
 * This returns the FD at position @index and then drops it form the fdlist, by
 * replacing it with -1.
 *
 * If @index points outside the fdlist range, or if the FD was already stolen,
 * -1 is returned.
 *
 * Return: The FD at position @index is returned.
 */
int fdlist_steal(FDList *list, size_t index) {
        int *p, fd = -1;

        p = fdlist_data(list);

        if (index < fdlist_count(list)) {
                fd = p[index];
                p[index] = -1;
        }

        return fd;
}
