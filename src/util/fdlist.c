/*
 * File-Descriptor List
 */

#include <c-macro.h>
#include <stdlib.h>
#include <sys/socket.h>
#include "fdlist.h"

int fdlist_new_with_fds(FDList **listp, const int *fds, size_t n_fds) {
        FDList *list;

        list = malloc(sizeof(*list) + CMSG_SPACE(n_fds * sizeof(int)));
        if (!list)
                return -ENOMEM;

        list->consumed = false;
        list->cmsg->cmsg_len = CMSG_LEN(n_fds * sizeof(int));
        list->cmsg->cmsg_level = SOL_SOCKET;
        list->cmsg->cmsg_type = SCM_RIGHTS;
        memcpy(fdlist_data(list), fds, n_fds * sizeof(int));

        *listp = list;
        return 0;
}

int fdlist_new_consume_fds(FDList **listp, const int *fds, size_t n_fds) {
        int r;

        r = fdlist_new_with_fds(listp, fds, n_fds);
        if (!r)
                (*listp)->consumed = true;

        return r;
}

FDList *fdlist_free(FDList *list) {
        size_t i, n;
        int *p;

        if (list) {
                p = fdlist_data(list);
                n = fdlist_count(list);

                if (list->consumed)
                        for (i = 0; i < n; ++i)
                                close(p[i]);

                free(list);
        }

        return NULL;
}

void fdlist_truncate(FDList *list, size_t n_fds) {
        size_t i, n;
        int *p;

        p = fdlist_data(list);
        n = fdlist_count(list);

        assert(n_fds <= n);

        if (list->consumed)
                for (i = n_fds; i < n; ++i)
                        close(p[i]);

        list->cmsg->cmsg_len = CMSG_LEN(n_fds * sizeof(int));
}
