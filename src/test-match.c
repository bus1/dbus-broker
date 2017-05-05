/*
 * Test Bus Context
 */

#include <c-macro.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "bus.h"
#include "match.h"
#include "peer.h"

static void test_args(Peer *peer,
                      const char *match,
                      const char *arg0,
                      const char *arg1,
                      const char *arg2,
                      const char *arg3) {
        _c_cleanup_(match_rule_freep) MatchRule *rule = NULL;
        int r;

        r = match_rule_new(&rule, peer, match);
        assert(r == 0);
        assert(strcmp(rule->keys.filter.args[0], arg0) == 0);
        assert(strcmp(rule->keys.filter.args[1], arg1) == 0);
        assert(strcmp(rule->keys.filter.args[2], arg2) == 0);
        assert(strcmp(rule->keys.filter.args[3], arg3) == 0);
}

static void test_setup(void) {
        _c_cleanup_(bus_freep) Bus *bus = NULL;
        _c_cleanup_(peer_freep) Peer *peer = NULL;
        int pair[2], r;

        r = bus_new(&bus, 1024, 1024, 1024, 1024, 1024);
        assert(r >= 0);

        r = socketpair(AF_UNIX, SOCK_STREAM, 0, pair);
        assert(r >= 0);

        r = peer_new_with_fd(&peer, bus, pair[0]);
        assert(r >= 0);

        /* examples taken from the spec */
        test_args(peer, "arg0=''\\''',arg1='\\',arg2=',',arg3='\\\\'",
                  "\'", "\\", ",", "\\\\");
        test_args(peer, "arg0=\\',arg1=\\,arg2=',',arg3=\\\\",
                  "\'", "\\", ",", "\\\\");

        close(pair[1]);
}

int main(int argc, char **argv) {
        test_setup();
        return 0;
}
