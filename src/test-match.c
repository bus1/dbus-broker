/*
 * Test Bus Context
 */

#include <c-macro.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "match.h"

static void test_args(MatchOwner *owner,
                      const char *match,
                      const char *arg0,
                      const char *arg1,
                      const char *arg2,
                      const char *arg3) {
        _c_cleanup_(match_rule_freep) MatchRule *rule = NULL;
        int r;

        r = match_rule_new(&rule, owner, match);
        assert(r == 0);
        assert(strcmp(rule->keys.filter.args[0], arg0) == 0);
        assert(strcmp(rule->keys.filter.args[1], arg1) == 0);
        assert(strcmp(rule->keys.filter.args[2], arg2) == 0);
        assert(strcmp(rule->keys.filter.args[3], arg3) == 0);
}

static void test_setup(void) {
        MatchOwner owner = {};

        /* examples taken from the spec */
        test_args(&owner, "arg0=''\\''',arg1='\\',arg2=',',arg3='\\\\'",
                  "\'", "\\", ",", "\\\\");
        test_args(&owner, "arg0=\\',arg1=\\,arg2=',',arg3=\\\\",
                  "\'", "\\", ",", "\\\\");

        match_owner_deinit(&owner);
}

int main(int argc, char **argv) {
        test_setup();
        return 0;
}
