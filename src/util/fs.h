#pragma once

/*
 * File System Helpers
 */

#include <c-stdaux.h>
#include <dirent.h>
#include <stdlib.h>
#include <sys/types.h>

typedef struct FsDirlist FsDirlist;

enum {
        FS_DIR_FLAG_NO_HIDDEN   = (1U << 0),
};

struct FsDirlist {
        size_t n_entries;
        size_t n_allocated;
        struct dirent **entries;
};

/* dirlist */

int fs_dirlist_new(FsDirlist **listp, size_t n_allocated);
FsDirlist *fs_dirlist_free(FsDirlist *list);

int fs_dirlist_push(FsDirlist *list, const struct dirent *de);
void fs_dirlist_sort(FsDirlist *list);

C_DEFINE_CLEANUP(FsDirlist *, fs_dirlist_free);

/* dir */

int fs_dir_list(DIR *dir, FsDirlist **listp, unsigned int flags);
