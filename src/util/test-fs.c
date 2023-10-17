/*
 * Test File System Helpers
 */

#undef NDEBUG
#include <c-stdaux.h>
#include <dirent.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include "util/fs.h"
#include "util/string.h"

static void test_dir_list(void) {
        _c_cleanup_(c_closedirp) DIR *dir = NULL;
        _c_cleanup_(fs_dirlist_freep) FsDirlist *list = NULL;
        const char *req[] = {
                "bin",
                "dev",
                "etc",
                "lib",
                "proc",
                "run",
                "sys",
                "tmp",
                "usr",
                "var",
        };
        size_t i, pos;
        int r;

        dir = opendir("/");
        c_assert(dir);

        r = fs_dir_list(dir, &list, 0);
        c_assert(!r);
        c_assert(list);
        c_assert(list->n_entries > 0);

        /* Verify all expected entries are found in order. */
        pos = 0;
        for (i = 0; i < list->n_entries; ++i) {
                if (pos >= C_ARRAY_SIZE(req))
                        break;

                if (string_equal(list->entries[i]->d_name, req[pos]))
                        ++pos;
        }
        c_assert(pos == C_ARRAY_SIZE(req));
}

int main(int argc, char **argv) {
        test_dir_list();
        return 0;
}
