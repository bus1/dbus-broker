#pragma once

/*
 * File-Descriptor List
 */

#include <c-stdaux.h>
#include <stdlib.h>
#include <sys/socket.h>

typedef struct FDList FDList;

struct FDList {
        bool consumed : 1;
        struct cmsghdr cmsg[];
};

int fdlist_new_with_fds(FDList **listp, const int *fds, size_t n_fds);
int fdlist_new_consume_fds(FDList **listp, const int *fds, size_t n_fds);
int fdlist_new_dup_fds(FDList **listp, const int *fds, size_t n_fds);
FDList *fdlist_free(FDList *list);
void fdlist_truncate(FDList *list, size_t n_fds);
int fdlist_steal(FDList *list, size_t index);

C_DEFINE_CLEANUP(FDList *, fdlist_free);

/* inline helpers */

static inline int *fdlist_data(FDList *list) {
        return list ? (int *)CMSG_DATA(list->cmsg) : NULL;
}

static inline size_t fdlist_count(FDList *list) {
        return list ? (list->cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int) : 0;
}

static inline size_t fdlist_size(FDList *list) {
        return list ? CMSG_SPACE(fdlist_count(list) * sizeof(int)) : 0;
}

static inline int fdlist_get(FDList *list, size_t index) {
        return index < fdlist_count(list) ? fdlist_data(list)[index] : -1;
}
