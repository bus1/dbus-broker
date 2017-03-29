/*
 * Test Bus Context
 */

#include <c-macro.h>
#include <stdlib.h>
#include "bus.h"
#include "dbus-match.h"
#include "peer.h"

static void test_args(const char *match,
                      const char *arg0,
                      const char *arg1,
                      const char *arg2,
                      const char *arg3) {
        DBusMatchKeys keys = {};
        char buffer[strlen(match)];
        int r;

        r = dbus_match_keys_parse(&keys, buffer, match, strlen(match));
        assert(r >= 0);
        assert(strcmp(keys.args[0], arg0) == 0);
        assert(strcmp(keys.args[1], arg1) == 0);
        assert(strcmp(keys.args[2], arg2) == 0);
        assert(strcmp(keys.args[3], arg3) == 0);
}

static void test_setup(void) {
        /* examples taken from the spec */
        test_args("arg0=''\\''',arg1='\\',arg2=',',arg3='\\\\'",
                  "\'", "\\", ",", "\\\\");
        test_args("arg0=\\',arg1=\\,arg2=',',arg3=\\\\",
                  "\'", "\\", ",", "\\\\");
}

int main(int argc, char **argv) {
        test_setup();
        return 0;
}
