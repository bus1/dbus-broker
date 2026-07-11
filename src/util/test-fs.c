/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: D-Bus Broker Developers */

/*
 * Test File System Helpers
 */

#undef NDEBUG
#include <c-stdaux.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include "util/fs.h"
#include "util/string.h"

static void test_dir_list(void) {
        _c_cleanup_(c_closedirp) DIR *dir = NULL;
        _c_cleanup_(fs_dirlist_freep) FsDirlist *list = NULL;
        /* Deliberately listed out of sort order: the listing is specified to
         * come back sorted regardless of creation or readdir order. */
        const char *unsorted[] = {
                "foo",
                "bar",
                "07",
                "baz-2",
                "100",
                "baz-11",
        };
        const char *expected[] = {
                "07",
                "100",
                "bar",
                "baz-11",
                "baz-2",
                "foo",
        };
        char template[] = "/tmp/test-fs.XXXXXX";
        const char *root;
        size_t i, pos;
        int r, fd;

        /*
         * Build a private fixture directory rather than asserting on the
         * layout of the host's root directory: the latter depends on the
         * distribution (e.g., distributions without a merged /lib, minimal
         * container roots).
         */
        root = mkdtemp(template);
        c_assert(root);

        for (i = 0; i < C_ARRAY_SIZE(unsorted); ++i) {
                _c_cleanup_(c_freep) char *path = NULL;

                r = asprintf(&path, "%s/%s", root, unsorted[i]);
                c_assert(r > 0);

                fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
                c_assert(fd >= 0);
                close(fd);
        }

        dir = opendir(root);
        c_assert(dir);

        r = fs_dir_list(dir, &list, 0);
        c_assert(!r);
        c_assert(list);
        c_assert(list->n_entries == C_ARRAY_SIZE(expected));

        /* Verify all entries are returned, in sorted order. */
        pos = 0;
        for (i = 0; i < list->n_entries; ++i) {
                if (pos >= C_ARRAY_SIZE(expected))
                        break;

                if (string_equal(list->entries[i]->d_name, expected[pos]))
                        ++pos;
        }
        c_assert(pos == C_ARRAY_SIZE(expected));

        for (i = 0; i < C_ARRAY_SIZE(unsorted); ++i) {
                _c_cleanup_(c_freep) char *path = NULL;

                r = asprintf(&path, "%s/%s", root, unsorted[i]);
                c_assert(r > 0);
                unlink(path);
        }
        rmdir(root);
}

int main(int argc, char **argv) {
        test_dir_list();
        return 0;
}
