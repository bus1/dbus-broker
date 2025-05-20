/*
 * Test Bus Context
 */

#undef NDEBUG
#include <c-stdaux.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "bus/match.h"
#include "dbus/message.h"
#include "dbus/protocol.h"

static void test_arg(MatchOwner *owner,
                     const char *match,
                     const char *arg0) {
        _c_cleanup_(match_rule_user_unrefp) MatchRule *rule = NULL;
        int r;

        r = match_owner_ref_rule(owner, &rule, NULL, match, false);
        c_assert(r == 0);
        c_assert(strcmp(rule->keys.filter.args[0], arg0) == 0);
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

        r = match_owner_ref_rule(owner,  &rule, NULL, match, false);
        c_assert(r == 0);
        c_assert(strcmp(rule->keys.filter.args[0], arg0) == 0);
        c_assert(strcmp(rule->keys.filter.args[1], arg1) == 0);
        c_assert(strcmp(rule->keys.filter.args[2], arg2) == 0);
        c_assert(strcmp(rule->keys.filter.args[3], arg3) == 0);
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

        r = match_owner_ref_rule(owner, &rule, NULL, match, false);
        c_assert(r == 0 || r == MATCH_E_INVALID);

        return !r;
}

static void test_splitting(MatchOwner *owner) {
        c_assert(test_validity(owner, "arg0=foo,arg1=bar"));
        c_assert(test_validity(owner, "arg0=foo, arg1=bar"));
        c_assert(test_validity(owner, "arg0=foo, arg1=bar,"));
        c_assert(test_validity(owner, "arg0=foo, arg1=bar, "));
}

static void test_wildcard(MatchOwner *owner) {
        c_assert(test_validity(owner, ""));
        c_assert(test_validity(owner, "\n="));
}

static void test_validate_keys(MatchOwner *owner) {
        c_assert(!test_validity(owner, "foo=bar"));
        c_assert(test_validity(owner, "type=signal"));
        c_assert(!test_validity(owner, "type=signal,type=signal"));
        c_assert(test_validity(owner, "sender=foo.bar"));
        c_assert(!test_validity(owner, "sender=foo.bar,sender=foo.bar"));
        c_assert(test_validity(owner, "interface=foo.bar"));
        c_assert(!test_validity(owner, "interface=foo.bar,interface=foo.bar"));
        c_assert(test_validity(owner, "member=FooBar"));
        c_assert(!test_validity(owner, "member=FooBar,member=FooBar"));
        c_assert(test_validity(owner, "path=/org/foo"));
        c_assert(!test_validity(owner, "path=/org/foo,path=/org/foo"));
        c_assert(test_validity(owner, "path_namespace=/org/foo"));
        c_assert(!test_validity(owner, "path_namespace=/org/foo,path_namespace=/org/foo"));
        c_assert(!test_validity(owner, "path_namespace=/org/foo,path=/org/foo")); /* cannot be mixed */
        c_assert(test_validity(owner, "destination=foo.bar"));
        c_assert(!test_validity(owner, "destination=foo.bar,destination=foo.bar"));
        c_assert(test_validity(owner, "arg0=foo"));
        c_assert(test_validity(owner, "arg63=foo"));
        c_assert(!test_validity(owner, "arg64=foo"));
        c_assert(!test_validity(owner, "arg0=foo,arg0=foo"));
        c_assert(!test_validity(owner, "arg0=foo,arg0path=foo")); /* cannot be mixed */
        c_assert(!test_validity(owner, "arg0=foo,arg0namespace=foo"));
        c_assert(test_validity(owner, "arg0path=foo"));
        c_assert(test_validity(owner, "arg63path=foo"));
        c_assert(!test_validity(owner, "arg64path=foo"));
        c_assert(!test_validity(owner, "arg0path=foo,arg0path=foo"));
        c_assert(!test_validity(owner, "arg0path=foo,arg0namespace=foo")); /* cannot be mixed */
        c_assert(test_validity(owner, "arg0namespace=foo"));
        c_assert(!test_validity(owner, "arg1namespace=foo"));
        c_assert(!test_validity(owner, "arg0namespace=foo,arg0namespace=foo"));
}

static void test_eavesdrop(MatchOwner *owner) {
        const char *match;
        int r;

        /* Verify that eavesdrop is not supported by default. */
        match = "eavesdrop=true";
        {
                _c_cleanup_(match_rule_user_unrefp) MatchRule *rule = NULL;

                r = match_owner_ref_rule(owner, &rule, NULL, match, false);
                c_assert(r == MATCH_E_INVALID);
        }

        /* Verify eavesdrop is allowed if explicitly requested. */
        match = "eavesdrop=true";
        {
                _c_cleanup_(match_rule_user_unrefp) MatchRule *rule = NULL;

                r = match_owner_ref_rule(owner, &rule, NULL, match, true);
                c_assert(!r);
        }

        /* Verify only `true` and `false` are allowed. */
        match = "eavesdrop=foobar";
        {
                _c_cleanup_(match_rule_user_unrefp) MatchRule *rule = NULL;

                r = match_owner_ref_rule(owner, &rule, NULL, match, true);
                c_assert(r == MATCH_E_INVALID);
        }
}

static bool test_match(const char *match_string, MessageMetadata *metadata) {
        CList subscribers = C_LIST_INIT(subscribers);
        MatchRegistry registry;
        MatchOwner owner, *owner1;
        MatchRule *rule;
        int r;

        match_registry_init(&registry);
        match_owner_init(&owner);

        r = match_owner_ref_rule(&owner, &rule, NULL, match_string, false);
        c_assert(!r);

        r = match_rule_link(rule, NULL, &registry, false);
        c_assert(!r);

        match_registry_get_subscribers(&registry, &subscribers, metadata);
        owner1 = c_list_first_entry(&subscribers, MatchOwner, destinations_link);
        c_assert(!owner1 || owner1 == &owner);
        c_list_flush(&subscribers);

        match_rule_user_unref(rule);
        match_owner_deinit(&owner);
        match_registry_deinit(&registry);

        return !!(owner1 == &owner);
}

static void test_individual_matches(void) {
        MessageMetadata metadata = MESSAGE_METADATA_INIT;

        c_assert(test_match("", &metadata));

        /* type */
        metadata = (MessageMetadata)MESSAGE_METADATA_INIT;
        c_assert(!test_match("type=signal", &metadata));
        metadata.header.type = DBUS_MESSAGE_TYPE_SIGNAL;
        c_assert(test_match("type=signal", &metadata));
        c_assert(!test_match("type=error", &metadata));

        /* destination: we do not support destination matching */
        metadata = (MessageMetadata)MESSAGE_METADATA_INIT;
        c_assert(test_match("destination=:1.0", &metadata));
        c_assert(test_match("destination=:1.1", &metadata));

        /* interface */
        metadata = (MessageMetadata)MESSAGE_METADATA_INIT;
        c_assert(!test_match("interface=com.example.foo", &metadata));
        metadata.fields.interface = "com.example.foo";
        c_assert(test_match("interface=com.example.foo", &metadata));
        c_assert(!test_match("interface=com.example.bar", &metadata));

        /* member */
        metadata = (MessageMetadata)MESSAGE_METADATA_INIT;
        c_assert(!test_match("member=FooBar", &metadata));
        metadata.fields.member = "FooBar";
        c_assert(test_match("member=FooBar", &metadata));
        c_assert(!test_match("member=FooBaz", &metadata));

        /* path */
        metadata = (MessageMetadata)MESSAGE_METADATA_INIT;
        c_assert(!test_match("path=/com/example/foo", &metadata));
        metadata.fields.path = "/com/example/foo";
        c_assert(test_match("path=/com/example/foo", &metadata));
        c_assert(!test_match("path=/com/example/bar", &metadata));
        c_assert(!test_match("path=/com/example", &metadata));
        c_assert(!test_match("path=/com/example/foo/bar", &metadata));

        /* path_namespace */
        metadata = (MessageMetadata)MESSAGE_METADATA_INIT;
        c_assert(!test_match("path_namespace=/com/example/foo", &metadata));
        metadata.fields.path = "/com/example/foo";
        c_assert(test_match("path_namespace=/com/example/foo", &metadata));
        c_assert(!test_match("path_namespace=/com/example/foo/bar", &metadata));
        c_assert(!test_match("path_namespace=/com/example/foobar", &metadata));
        c_assert(test_match("path_namespace=/com/example", &metadata));
        c_assert(!test_match("path_namespace=/com/ex", &metadata));
        c_assert(test_match("path_namespace=/com", &metadata));
        /* XXX: This fails but shouldn't! */
        /* c_assert(test_match("path_namespace=/", &metadata)); */

        /* arg0 */
        metadata = (MessageMetadata)MESSAGE_METADATA_INIT;
        c_assert(!test_match("arg0=/com/example/foo/", &metadata));
        metadata.args[0].value = "/com/example/foo/";
        metadata.args[0].element = 's';
        metadata.n_args = 1;
        c_assert(test_match("arg0=/com/example/foo/", &metadata));
        c_assert(!test_match("arg0=/com/example/foo/bar", &metadata));
        c_assert(!test_match("arg0=/com/example/foobar", &metadata));
        c_assert(!test_match("arg0=/com/example/", &metadata));
        c_assert(!test_match("arg0=/com/example", &metadata));
        metadata.args[0].value = "/com/example/foo";
        metadata.args[0].element = 's';
        c_assert(test_match("arg0=/com/example/foo", &metadata));
        c_assert(!test_match("arg0=/com/example/foo/bar", &metadata));
        c_assert(!test_match("arg0=/com/example/foobar", &metadata));
        c_assert(!test_match("arg0=/com/example/", &metadata));
        c_assert(!test_match("arg0=/com/example", &metadata));
        metadata.args[0].value = "com.example.foo";
        metadata.args[0].element = 's';
        c_assert(test_match("arg0=com.example.foo", &metadata));
        c_assert(!test_match("arg0=com.example.foo.bar", &metadata));
        c_assert(!test_match("arg0=com.example.foobar", &metadata));
        c_assert(!test_match("arg0=com.example", &metadata));

        /* arg1 */
        metadata = (MessageMetadata)MESSAGE_METADATA_INIT;
        c_assert(!test_match("arg1=/com/example/foo/", &metadata));
        metadata.args[0].value = "unrelated string";
        metadata.args[0].element = 's';
        metadata.args[1].value = "/com/example/foo/";
        metadata.args[1].element = 's';
        metadata.n_args = 2;
        c_assert(test_match("arg1=/com/example/foo/", &metadata));
        c_assert(!test_match("arg1=/com/example/foo/bar", &metadata));
        c_assert(!test_match("arg1=/com/example/foobar", &metadata));
        c_assert(!test_match("arg1=/com/example/", &metadata));
        c_assert(!test_match("arg1=/com/example", &metadata));
        metadata.args[1].value = "/com/example/foo";
        metadata.args[1].element = 's';
        c_assert(test_match("arg1=/com/example/foo", &metadata));
        c_assert(!test_match("arg1=/com/example/foo/bar", &metadata));
        c_assert(!test_match("arg1=/com/example/foobar", &metadata));
        c_assert(!test_match("arg1=/com/example/", &metadata));
        c_assert(!test_match("arg1=/com/example", &metadata));
        metadata.args[1].value = "com.example.foo";
        metadata.args[1].element = 's';
        c_assert(test_match("arg1=com.example.foo", &metadata));
        c_assert(!test_match("arg1=com.example.foo.bar", &metadata));
        c_assert(!test_match("arg1=com.example.foobar", &metadata));
        c_assert(!test_match("arg1=com.example", &metadata));

        /* arg0path - parent */
        metadata = (MessageMetadata)MESSAGE_METADATA_INIT;
        c_assert(!test_match("arg0path=/com/example/foo/", &metadata));
        metadata.args[0].value = "/com/example/foo/";
        metadata.args[0].element = 'o';
        metadata.n_args = 1;
        c_assert(test_match("arg0path=/com/example/foo/", &metadata));
        c_assert(test_match("arg0path=/com/example/foo/bar", &metadata));
        c_assert(!test_match("arg0path=/com/example/foobar", &metadata));
        c_assert(test_match("arg0path=/com/example/", &metadata));
        c_assert(!test_match("arg0path=/com/example", &metadata));

        /* arg0path - child */
        metadata = (MessageMetadata)MESSAGE_METADATA_INIT;
        c_assert(!test_match("arg0path=/com/example/foo", &metadata));
        metadata.args[0].value = "/com/example/foo";
        metadata.args[0].element = 'o';
        metadata.n_args = 1;
        c_assert(test_match("arg0path=/com/example/foo", &metadata));
        c_assert(!test_match("arg0path=/com/example/foo/bar", &metadata));
        c_assert(!test_match("arg0path=/com/example/foobar", &metadata));
        c_assert(test_match("arg0path=/com/example/", &metadata));
        c_assert(!test_match("arg0path=/com/example", &metadata));

        /* arg1path - parent */
        metadata = (MessageMetadata)MESSAGE_METADATA_INIT;
        c_assert(!test_match("arg1path=/com/example/foo/", &metadata));
        metadata.args[0].value = "unrelated string";
        metadata.args[0].element = 's';
        metadata.args[1].value = "/com/example/foo/";
        metadata.args[1].element = 'o';
        metadata.n_args = 2;
        c_assert(test_match("arg1path=/com/example/foo/", &metadata));
        c_assert(test_match("arg1path=/com/example/foo/bar", &metadata));
        c_assert(!test_match("arg1path=/com/example/foobar", &metadata));
        c_assert(test_match("arg1path=/com/example/", &metadata));
        c_assert(!test_match("arg1path=/com/example", &metadata));

        /* arg1path - child */
        metadata = (MessageMetadata)MESSAGE_METADATA_INIT;
        c_assert(!test_match("arg1path=/com/example/foo", &metadata));
        metadata.args[0].value = "unrelated string";
        metadata.args[0].element = 's';
        metadata.args[1].value = "/com/example/foo";
        metadata.args[1].element = 'o';
        metadata.n_args = 2;
        c_assert(test_match("arg1path=/com/example/foo", &metadata));
        c_assert(!test_match("arg1path=/com/example/foo/bar", &metadata));
        c_assert(!test_match("arg1path=/com/example/foobar", &metadata));
        c_assert(test_match("arg1path=/com/example/", &metadata));
        c_assert(!test_match("arg1path=/com/example", &metadata));

        /* arg0namespace */
        metadata = (MessageMetadata)MESSAGE_METADATA_INIT;
        c_assert(!test_match("arg0namespace=com.example.foo", &metadata));
        metadata.args[0].value = "com.example.foo";
        metadata.args[0].element = 's';
        metadata.n_args = 1;
        c_assert(test_match("arg0namespace=com.example.foo", &metadata));
        c_assert(!test_match("arg0namespace=com.example.foo.bar", &metadata));
        c_assert(!test_match("arg0namespace=com.example.foobar", &metadata));
        c_assert(test_match("arg0namespace=com.example", &metadata));
        c_assert(!test_match("arg0namespace=com.ex", &metadata));
        c_assert(test_match("arg0namespace=com", &metadata));
}

static void test_iterator(void) {
        MatchRegistry registry = MATCH_REGISTRY_INIT(registry);
        CList subscribers = C_LIST_INIT(subscribers);
        MessageMetadata metadata = MESSAGE_METADATA_INIT;
        MatchOwner owner1, owner2, *owner;
        MatchRule *rule1, *rule2, *rule3, *rule4;
        int r;

        match_owner_init(&owner1);
        match_owner_init(&owner2);

        r = match_owner_ref_rule(&owner1, &rule1, NULL, "", false);
        c_assert(!r);

        r = match_rule_link(rule1, NULL, &registry, false);
        c_assert(!r);

        r = match_owner_ref_rule(&owner1, &rule2, NULL, "", false);
        c_assert(!r);

        r = match_rule_link(rule2, NULL, &registry, false);
        c_assert(!r);

        r = match_owner_ref_rule(&owner2, &rule3, NULL, "", false);
        c_assert(!r);

        r = match_rule_link(rule3, NULL, &registry, false);
        c_assert(!r);

        r = match_owner_ref_rule(&owner2, &rule4, NULL, "", false);
        c_assert(!r);

        r = match_rule_link(rule4, NULL, &registry, false);
        c_assert(!r);

        match_registry_get_subscribers(&registry, &subscribers, &metadata);

        owner = c_list_first_entry(&subscribers, MatchOwner, destinations_link);
        c_list_unlink(&owner->destinations_link);
        c_assert(owner == &owner1);

        owner = c_list_first_entry(&subscribers, MatchOwner, destinations_link);
        c_list_unlink(&owner->destinations_link);
        c_assert(owner == &owner2);

        match_rule_user_unref(rule4);
        match_rule_user_unref(rule3);
        match_rule_user_unref(rule2);
        match_rule_user_unref(rule1);
        match_owner_deinit(&owner2);
        match_owner_deinit(&owner1);
        match_registry_deinit(&registry);
}

static void test_counters(void) {
        MatchCounters counters = MATCH_COUNTERS_INIT;
        MatchRegistry registry = MATCH_REGISTRY_INIT(registry);
        MatchOwner owner1, owner2;
        MatchRule *rule1, *rule2, *rule3, *rule4;
        int r;

        match_owner_init(&owner1);
        match_owner_init(&owner2);

        c_assert(owner1.n_owner_subscriptions == 0);
        c_assert(owner2.n_owner_subscriptions == 0);
        c_assert(counters.n_subscriptions == 0);
        c_assert(counters.n_subscriptions_peak == 0);
        c_assert(counters.n_owner_subscriptions_peak == 0);

        /* owner1: install a new match */

        r = match_owner_ref_rule(&owner1, &rule1, NULL, "path=/a", false);
        c_assert(!r);

        r = match_rule_link(rule1, &counters, &registry, false);
        c_assert(!r);

        c_assert(owner1.n_owner_subscriptions == 1);
        c_assert(owner2.n_owner_subscriptions == 0);
        c_assert(counters.n_subscriptions == 1);
        c_assert(counters.n_subscriptions_peak == 1);
        c_assert(counters.n_owner_subscriptions_peak == 1);

        /* owner1: install the same match again */

        r = match_owner_ref_rule(&owner1, &rule2, NULL, "path=/a", false);
        c_assert(!r);

        r = match_rule_link(rule2, &counters, &registry, false);
        c_assert(!r);

        c_assert(owner1.n_owner_subscriptions == 1);
        c_assert(owner2.n_owner_subscriptions == 0);
        c_assert(counters.n_subscriptions == 1);
        c_assert(counters.n_subscriptions_peak == 1);
        c_assert(counters.n_owner_subscriptions_peak == 1);

        /* owner2: install a new match */

        r = match_owner_ref_rule(&owner2, &rule3, NULL, "path=/a", false);
        c_assert(!r);

        r = match_rule_link(rule3, &counters, &registry, false);
        c_assert(!r);

        c_assert(owner1.n_owner_subscriptions == 1);
        c_assert(owner2.n_owner_subscriptions == 1);
        c_assert(counters.n_subscriptions == 2);
        c_assert(counters.n_subscriptions_peak == 2);
        c_assert(counters.n_owner_subscriptions_peak == 1);

        /* owner2: install another match */

        r = match_owner_ref_rule(&owner2, &rule4, NULL, "path=/b", false);
        c_assert(!r);

        r = match_rule_link(rule4, &counters, &registry, false);
        c_assert(!r);

        c_assert(owner1.n_owner_subscriptions == 1);
        c_assert(owner2.n_owner_subscriptions == 2);
        c_assert(counters.n_subscriptions == 3);
        c_assert(counters.n_subscriptions_peak == 3);
        c_assert(counters.n_owner_subscriptions_peak == 2);

        match_rule_user_unref(rule4);
        match_rule_user_unref(rule3);
        match_rule_user_unref(rule2);
        match_rule_user_unref(rule1);

        c_assert(owner1.n_owner_subscriptions == 0);
        c_assert(owner2.n_owner_subscriptions == 0);
        c_assert(counters.n_subscriptions == 0);
        c_assert(counters.n_subscriptions_peak == 3);
        c_assert(counters.n_owner_subscriptions_peak == 2);

        match_owner_deinit(&owner2);
        match_owner_deinit(&owner1);
        match_registry_deinit(&registry);
}

int main(int argc, char **argv) {
        MatchOwner owner = MATCH_OWNER_INIT(owner);

        test_splitting(&owner);
        test_parse_key(&owner);
        test_parse_value(&owner);
        test_wildcard(&owner);
        test_validate_keys(&owner);
        test_eavesdrop(&owner);

        test_individual_matches();
        test_iterator();
        test_counters();

        match_owner_deinit(&owner);
        return 0;
}
