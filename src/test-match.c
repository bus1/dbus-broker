/*
 * Test Bus Context
 */

#include <c-macro.h>
#include <stdlib.h>
#include "bus.h"
#include "dbus-match.h"
#include "peer.h"

static void test_args(Bus *bus,
                      const char *match_string,
                      const char *arg0,
                      const char *arg1,
                      const char *arg2,
                      const char *arg3) {
        _c_cleanup_(peer_freep) Peer *peer = NULL;
        DBusMatchEntry *match;
        int r;

        r = peer_new(bus, &peer, -1, 1, 0, NULL, 0);
        assert(r >= 0);

        r = dbus_match_entry_new(&match, &bus->matches, peer, match_string);
        assert(r >= 0);
        assert(strcmp(match->arg[0], arg0) == 0);
        assert(strcmp(match->arg[1], arg1) == 0);
        assert(strcmp(match->arg[2], arg2) == 0);
        assert(strcmp(match->arg[3], arg3) == 0);
}

static void test_setup(void) {
        _c_cleanup_(bus_freep) Bus *bus = NULL;
        int r;

        r = bus_new(&bus, -1, 1024, 1024, 1024, 1024, 1024);
        assert(r >= 0);

        /* examples taken from the spec */
        test_args(bus, "arg0=''\\''',arg1='\\',arg2=',',arg3='\\\\'",
                  "\'", "\\", ",", "\\\\");
        test_args(bus, "arg0=\\',arg1=\\,arg2=',',arg3=\\\\",
                  "\'", "\\", ",", "\\\\");
}

int main(int argc, char **argv) {
        test_setup();
        return 0;
}
