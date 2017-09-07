/*
 * Test Bus Context
 */

#include <c-macro.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "bus/match.h"
#include "dbus/protocol.h"

static void test_arg(MatchOwner *owner,
                     const char *match,
                     const char *arg0) {
        _c_cleanup_(match_rule_user_unrefp) MatchRule *rule = NULL;
        int r;

        r = match_owner_ref_rule(owner, &rule, NULL, match);
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
        _c_cleanup_(match_rule_user_unrefp) MatchRule *rule = NULL;
        int r;

        r = match_owner_ref_rule(owner,  &rule, NULL, match);
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
        _c_cleanup_(match_rule_user_unrefp) MatchRule *rule = NULL;
        int r;

        r = match_owner_ref_rule(owner, &rule, NULL, match);
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

static void test_validate_keys(MatchOwner *owner) {
        assert(!test_validity(owner, "foo=bar"));
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
}

static bool test_match(const char *match_string, MatchFilter *filter) {
        MatchRegistry registry;
        MatchOwner owner;
        MatchRule *rule, *rule1;
        int r;

        match_registry_init(&registry);
        match_owner_init(&owner);

        r = match_owner_ref_rule(&owner, &rule, NULL, match_string);
        assert(!r);

        match_rule_link(rule, &registry, false);

        rule1 = match_rule_next_match(&registry, NULL, filter);
        assert(!rule1 || rule1 == rule);

        match_rule_user_unref(rule);
        match_owner_deinit(&owner);
        match_registry_deinit(&registry);

        return !!(rule1 == rule);
}

static void test_individual_matches(void) {
        MatchFilter filter = MATCH_FILTER_INIT;

        assert(test_match("", &filter));

        /* type */
        filter = (MatchFilter)MATCH_FILTER_INIT;
        assert(!test_match("type=signal", &filter));
        filter.type = DBUS_MESSAGE_TYPE_SIGNAL;
        assert(test_match("type=signal", &filter));
        assert(!test_match("type=error", &filter));

        /* destination */
        filter = (MatchFilter)MATCH_FILTER_INIT;
        assert(!test_match("destination=:1.0", &filter));
        filter.destination = 0;
        assert(!test_match("", &filter));
        assert(!test_match("destination=:1.0", &filter));
        assert(!test_match("destination=:1.1", &filter));

        /* interface */
        filter = (MatchFilter)MATCH_FILTER_INIT;
        assert(!test_match("interface=com.example.foo", &filter));
        filter.interface = "com.example.foo";
        assert(test_match("interface=com.example.foo", &filter));
        assert(!test_match("interface=com.example.bar", &filter));

        /* member */
        filter = (MatchFilter)MATCH_FILTER_INIT;
        assert(!test_match("member=FooBar", &filter));
        filter.member = "FooBar";
        assert(test_match("member=FooBar", &filter));
        assert(!test_match("member=FooBaz", &filter));

        /* path */
        filter = (MatchFilter)MATCH_FILTER_INIT;
        assert(!test_match("path=/com/example/foo", &filter));
        filter.path = "/com/example/foo";
        assert(test_match("path=/com/example/foo", &filter));
        assert(!test_match("path=/com/example/bar", &filter));
        assert(!test_match("path=/com/example", &filter));
        assert(!test_match("path=/com/example/foo/bar", &filter));

        /* path_namespace */
        filter = (MatchFilter)MATCH_FILTER_INIT;
        assert(!test_match("path_namespace=/com/example/foo", &filter));
        filter.path = "/com/example/foo";
        assert(test_match("path_namespace=/com/example/foo", &filter));
        assert(!test_match("path_namespace=/com/example/foo/bar", &filter));
        assert(!test_match("path_namespace=/com/example/foobar", &filter));
        assert(test_match("path_namespace=/com/example", &filter));
        assert(!test_match("path_namespace=/com/ex", &filter));
        assert(test_match("path_namespace=/com", &filter));
        /* XXX: This fails but shouldn't! */
        /* assert(test_match("path_namespace=/", &filter)); */

        /* arg0 */
        filter = (MatchFilter)MATCH_FILTER_INIT;
        assert(!test_match("arg0=/com/example/foo/", &filter));
        filter.args[0] = "/com/example/foo/";
        assert(test_match("arg0=/com/example/foo/", &filter));
        assert(!test_match("arg0=/com/example/foo/bar", &filter));
        assert(!test_match("arg0=/com/example/foobar", &filter));
        assert(!test_match("arg0=/com/example/", &filter));
        assert(!test_match("arg0=/com/example", &filter));
        filter.args[0] = "/com/example/foo";
        assert(test_match("arg0=/com/example/foo", &filter));
        assert(!test_match("arg0=/com/example/foo/bar", &filter));
        assert(!test_match("arg0=/com/example/foobar", &filter));
        assert(!test_match("arg0=/com/example/", &filter));
        assert(!test_match("arg0=/com/example", &filter));
        filter.args[0] = "com.example.foo";
        assert(test_match("arg0=com.example.foo", &filter));
        assert(!test_match("arg0=com.example.foo.bar", &filter));
        assert(!test_match("arg0=com.example.foobar", &filter));
        assert(!test_match("arg0=com.example", &filter));

        /* arg0path - parent */
        filter = (MatchFilter)MATCH_FILTER_INIT;
        assert(!test_match("arg0path=/com/example/foo/", &filter));
        filter.argpaths[0] = "/com/example/foo/";
        assert(test_match("arg0path=/com/example/foo/", &filter));
        assert(test_match("arg0path=/com/example/foo/bar", &filter));
        assert(!test_match("arg0path=/com/example/foobar", &filter));
        assert(test_match("arg0path=/com/example/", &filter));
        assert(!test_match("arg0path=/com/example", &filter));

        /* arg0path - child */
        filter = (MatchFilter)MATCH_FILTER_INIT;
        assert(!test_match("arg0path=/com/example/foo", &filter));
        filter.argpaths[0] = "/com/example/foo";
        assert(test_match("arg0path=/com/example/foo", &filter));
        assert(!test_match("arg0path=/com/example/foo/bar", &filter));
        assert(!test_match("arg0path=/com/example/foobar", &filter));
        assert(test_match("arg0path=/com/example/", &filter));
        assert(!test_match("arg0path=/com/example", &filter));

        /* arg0namespace */
        filter = (MatchFilter)MATCH_FILTER_INIT;
        assert(!test_match("arg0namespace=com.example.foo", &filter));
        filter.args[0] = "com.example.foo";
        assert(test_match("arg0namespace=com.example.foo", &filter));
        assert(!test_match("arg0namespace=com.example.foo.bar", &filter));
        assert(!test_match("arg0namespace=com.example.foobar", &filter));
        assert(test_match("arg0namespace=com.example", &filter));
        assert(!test_match("arg0namespace=com.ex", &filter));
        assert(test_match("arg0namespace=com", &filter));
}

static void test_iterator(void) {
        MatchRegistry registry = MATCH_REGISTRY_INIT(registry);
        MatchFilter filter = MATCH_FILTER_INIT;
        MatchOwner owner1, owner2;
        MatchRule *rule, *rule1, *rule2, *rule3, *rule4;
        int r;

        match_owner_init(&owner1);
        match_owner_init(&owner2);

        r = match_owner_ref_rule(&owner1, &rule1, NULL, "");
        assert(!r);

        match_rule_link(rule1, &registry, false);

        r = match_owner_ref_rule(&owner1, &rule2, NULL, "");
        assert(!r);

        match_rule_link(rule2, &registry, false);

        r = match_owner_ref_rule(&owner2, &rule3, NULL, "");
        assert(!r);

        match_rule_link(rule3, &registry, false);

        r = match_owner_ref_rule(&owner2, &rule4, NULL, "");
        assert(!r);

        match_rule_link(rule4, &registry, false);

        rule = match_rule_next_match(&registry, NULL, &filter);
        assert(rule == rule1);

        rule = match_rule_next_match(&registry, rule, &filter);
        assert(rule == rule3);

        rule = match_rule_next_match(&registry, rule, &filter);
        assert(!rule);

        match_rule_user_unref(rule4);
        match_rule_user_unref(rule3);
        match_rule_user_unref(rule2);
        match_rule_user_unref(rule1);
        match_owner_deinit(&owner2);
        match_owner_deinit(&owner1);
        match_registry_deinit(&registry);

}

int main(int argc, char **argv) {
        MatchOwner owner = {};

        test_splitting(&owner);
        test_parse_key(&owner);
        test_parse_value(&owner);
        test_wildcard(&owner);
        test_validate_keys(&owner);

        test_individual_matches();

        test_iterator();

        match_owner_deinit(&owner);
        return 0;
}
