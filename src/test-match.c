/*
 * Test Bus Context
 */

#include <c-macro.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "match.h"

static void test_arg(MatchOwner *owner,
                     const char *match,
                     const char *arg0) {
        _c_cleanup_(match_rule_freep) MatchRule *rule = NULL;
        int r;

        r = match_rule_new(&rule, owner, match);
        assert(r == 0);
        assert(strcmp(rule->keys.filter.args[0], arg0) == 0);
}

static void test_parse_key(MatchOwner *owner) {
        test_arg(owner, "arg0=foo", "foo");
        test_arg(owner, " \t\n\r=arg0 \t\n\r=foo", "foo");
        test_arg(owner, "===arg0=foo", "foo");
}

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

static void test_parse_value(MatchOwner *owner) {
        /* examples taken from the spec */
        test_args(owner,
                  "arg0=''\\''',arg1='\\',arg2=',',arg3='\\\\'",
                  "\'",
                  "\\",
                  ",",
                  "\\\\");
        test_args(owner,
                  "arg0=\\',arg1=\\,arg2=',',arg3=\\\\",
                  "\'",
                  "\\",
                  ",",
                  "\\\\");
}

static void test_validity(MatchOwner *owner, const char *match, bool valid) {
        _c_cleanup_(match_rule_freep) MatchRule *rule = NULL;
        int r;

        r = match_rule_new(&rule, owner, match);
        assert(r == (valid ? 0 : MATCH_E_INVALID));
}

static void test_splitting(MatchOwner *owner) {
        test_validity(owner, "arg0=foo,arg1=bar", true);
        test_validity(owner, "arg0=foo, arg1=bar", true);
        test_validity(owner, "arg0=foo, arg1=bar,", true);
        test_validity(owner, "arg0=foo, arg1=bar, ", true);
}

static void test_wildcard(MatchOwner *owner) {
        test_validity(owner, "", true);
        test_validity(owner, "\n=", true);
}

static void test_eavesdrop(MatchOwner *owner, const char *match, bool eavesdrop) {
        _c_cleanup_(match_rule_freep) MatchRule *rule = NULL;
        int r;

        r = match_rule_new(&rule, owner, match);
        assert(r == 0);
        assert(rule->keys.eavesdrop == eavesdrop);
}

static void test_duplicates(MatchOwner *owner) {
        test_validity(owner, "type=signal", true);
        test_validity(owner, "type=signal,type=signal", false);
        test_validity(owner, "sender=foo.bar", true);
        test_validity(owner, "sender=foo.bar,sender=foo.bar", false);
        test_validity(owner, "interface=foo.bar", true);
        test_validity(owner, "interface=foo.bar,interface=foo.bar", false);
        test_validity(owner, "member=FooBar", true);
        test_validity(owner, "member=FooBar,member=FooBar", false);
        test_validity(owner, "path=/org/foo", true);
        test_validity(owner, "path=/org/foo,path=/org/foo", false);
        test_validity(owner, "path_namespace=/org/foo", true);
        test_validity(owner, "path_namespace=/org/foo,path_namespace=/org/foo", false);
        test_validity(owner, "path_namespace=/org/foo,path=/org/foo", false); /* cannot be mixed */
        test_validity(owner, "destination=foo.bar", true);
        test_validity(owner, "destination=foo.bar,destination=foo.bar", false);
        test_validity(owner, "arg0=foo", true);
        test_validity(owner, "arg0=foo,arg0=foo", false);
        test_validity(owner, "arg0=foo,arg0path=foo", false); /* cannot be mixed */
        test_validity(owner, "arg0=foo,arg0namespace=foo", false);
        test_validity(owner, "arg0path=foo", true);
        test_validity(owner, "arg0path=foo,arg0path=foo", false);
        test_validity(owner, "arg0path=foo,arg0namespace=foo", false); /* cannot be mixed */
        test_validity(owner, "arg0namespace=foo", true);
        test_validity(owner, "arg0namespace=foo,arg0namespace=foo", false);
        test_eavesdrop(owner, "", false);
        test_eavesdrop(owner, "eavesdrop=true", true);
        test_eavesdrop(owner, "eavesdrop=false", false);
        test_eavesdrop(owner, "eavesdrop=false,eavesdrop=true", true); /* allows overriding */
        test_eavesdrop(owner, "eavesdrop=true,eavesdrop=false", false);
}

int main(int argc, char **argv) {
        MatchOwner owner = {};

        test_splitting(&owner);
        test_parse_key(&owner);
        test_parse_value(&owner);
        test_wildcard(&owner);
        test_duplicates(&owner);

        match_owner_deinit(&owner);
        return 0;
}
