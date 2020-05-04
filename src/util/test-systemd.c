/*
 * Test systemd helpers
 */

#undef NDEBUG
#include <c-stdaux.h>
#include <stdlib.h>
#include "util/systemd.h"

static void test_systemd_escape_unit(void) {
        static const char * const from[] = {
                "foobar",
                "-foobar",
                "/foo/bar/",
                "\\foobar",
                ".foo.bar",
        };
        static const char * const to[] = {
                "foobar",
                "\\x2dfoobar",
                "-foo-bar-",
                "\\x5cfoobar",
                "\\x2efoo.bar",
        };

        for (size_t i = 0; i < C_ARRAY_SIZE(from); ++i) {
                _c_cleanup_(c_freep) char *e = NULL;
                int r;

                r = systemd_escape_unit(&e, from[i]);
                c_assert(!r);
                c_assert(!strcmp(e, to[i]));
        }
}

int main(int argc, char **argv) {
        test_systemd_escape_unit();
        return 0;
}
