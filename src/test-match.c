/*
 * Test Bus Context
 */

#include <c-macro.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "dbus/protocol.h"
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

static bool test_validity(MatchOwner *owner, const char *match) {
        _c_cleanup_(match_rule_freep) MatchRule *rule = NULL;
        int r;

        r = match_rule_new(&rule, owner, match);
        assert(r == 0 || r == MATCH_E_INVALID);

        return !r;
}

static void test_splitting(MatchOwner *owner) {
        assert(test_validity(owner, "arg0=foo,arg1=bar"));
        assert(test_validity(owner, "arg0=foo, arg1=bar"));
        assert(test_validity(owner, "arg0=foo, arg1=bar,"));
        assert(test_validity(owner, "arg0=foo, arg1=bar, "));
}

static void test_wildcard(MatchOwner *owner) {
        assert(test_validity(owner, ""));
        assert(test_validity(owner, "\n="));
}

static void test_eavesdrop(MatchOwner *owner, const char *match, bool eavesdrop) {
        _c_cleanup_(match_rule_freep) MatchRule *rule = NULL;
        int r;

        r = match_rule_new(&rule, owner, match);
        assert(r == 0);
        assert(rule->keys.eavesdrop == eavesdrop);
}

static void test_duplicates(MatchOwner *owner) {
        assert(test_validity(owner, "type=signal"));
        assert(!test_validity(owner, "type=signal,type=signal"));
        assert(test_validity(owner, "sender=foo.bar"));
        assert(!test_validity(owner, "sender=foo.bar,sender=foo.bar"));
        assert(test_validity(owner, "interface=foo.bar"));
        assert(!test_validity(owner, "interface=foo.bar,interface=foo.bar"));
        assert(test_validity(owner, "member=FooBar"));
        assert(!test_validity(owner, "member=FooBar,member=FooBar"));
        assert(test_validity(owner, "path=/org/foo"));
        assert(!test_validity(owner, "path=/org/foo,path=/org/foo"));
        assert(test_validity(owner, "path_namespace=/org/foo"));
        assert(!test_validity(owner, "path_namespace=/org/foo,path_namespace=/org/foo"));
        assert(!test_validity(owner, "path_namespace=/org/foo,path=/org/foo")); /* cannot be mixed */
        assert(test_validity(owner, "destination=foo.bar"));
        assert(!test_validity(owner, "destination=foo.bar,destination=foo.bar"));
        assert(test_validity(owner, "arg0=foo"));
        assert(test_validity(owner, "arg63=foo"));
        assert(!test_validity(owner, "arg64=foo"));
        assert(!test_validity(owner, "arg0=foo,arg0=foo"));
        assert(!test_validity(owner, "arg0=foo,arg0path=foo")); /* cannot be mixed */
        assert(!test_validity(owner, "arg0=foo,arg0namespace=foo"));
        assert(test_validity(owner, "arg0path=foo"));
        assert(test_validity(owner, "arg63path=foo"));
        assert(!test_validity(owner, "arg64path=foo"));
        assert(!test_validity(owner, "arg0path=foo,arg0path=foo"));
        assert(!test_validity(owner, "arg0path=foo,arg0namespace=foo")); /* cannot be mixed */
        assert(test_validity(owner, "arg0namespace=foo"));
        assert(!test_validity(owner, "arg1namespace=foo"));
        assert(!test_validity(owner, "arg0namespace=foo,arg0namespace=foo"));
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
