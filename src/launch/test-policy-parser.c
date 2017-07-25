/*
 * Test Policy
 */

#include <c-macro.h>
#include <stdlib.h>
#include "bus/policy.h"
#include "dbus/protocol.h"
#include "launch/policy-parser.h"

static void test_print_policy_decision(PolicyDecision *decision) {
        fprintf(stderr, "%s (%lu)\n", decision->deny ? "deny" : "allow", decision->priority);
}

static void test_print_policy_connect_tree(CRBTree *policy, const char *name, unsigned int indent) {
        PolicyConnectEntry *entry;

        if (c_rbtree_is_empty(policy))
                return;

        fprintf(stderr, "%*s%s:\n", indent * 4, "", name);

        c_rbtree_for_each_entry(entry, policy, rb) {
                fprintf(stderr, "%*s%u: ", (indent + 1) * 4, "", entry->uid);
                test_print_policy_decision(&entry->decision);
        }
}

static void test_print_policy_connect(PolicyConnect *policy, unsigned int indent) {
        if (policy_connect_is_empty(policy))
                return;

        fprintf(stderr, "%*sCONNECTION:\n", indent * 4, "");

        if (!policy_decision_is_default(&policy->wildcard)) {
                fprintf(stderr, "%*s*: ", (indent + 1) * 4, "");
                test_print_policy_decision(&policy->wildcard);
        }
        test_print_policy_connect_tree(&policy->gid_tree, "GID", indent + 1);
        test_print_policy_connect_tree(&policy->gid_tree, "UID", indent + 1);
}

static void test_print_policy_own_tree(CRBTree *policy, const char *suffix, unsigned int indent) {
        PolicyOwnEntry *entry;

        c_rbtree_for_each_entry(entry, policy, rb) {
                fprintf(stderr, "%*s%s%s: ", indent * 4, "", entry->name, suffix ?: "");
                test_print_policy_decision(&entry->decision);
        }
}

static void test_print_policy_own(PolicyOwn *policy, unsigned int indent) {
        if (policy_own_is_empty(policy))
                return;

        fprintf(stderr, "%*sOWN:\n", indent * 4, "");

        if (!policy_decision_is_default(&policy->wildcard)) {
                fprintf(stderr, "%*s*: ", (indent + 1) * 4, "");
                test_print_policy_decision(&policy->wildcard);
        }
        test_print_policy_own_tree(&policy->names, NULL, indent + 1);
        test_print_policy_own_tree(&policy->prefixes, ".*", indent + 1);
}

static void test_print_policy_xmit_entry(PolicyXmitEntry *entry, unsigned int indent) {
        if (entry->type) {
                const char *type = NULL;

                switch (entry->type) {
                case DBUS_MESSAGE_TYPE_METHOD_CALL:
                        type = "method_call";
                        break;
                case DBUS_MESSAGE_TYPE_METHOD_RETURN:
                        type = "method_return";
                        break;
                case DBUS_MESSAGE_TYPE_SIGNAL:
                        type = "signal";
                        break;
                case DBUS_MESSAGE_TYPE_ERROR:
                        type = "error";
                        break;
                }

                assert(type);

                fprintf(stderr, "%*stype: %s\n", indent * 4, "", type);
        }

        if (entry->interface)
                fprintf(stderr, "%*sinterface: %s\n", indent * 4, "", entry->interface);

        if (entry->member)
                fprintf(stderr, "%*smember: %s\n", indent * 4, "", entry->member);

        if (entry->path)
                fprintf(stderr, "%*spath: %s\n", indent * 4, "", entry->path);

        fprintf(stderr, "%*s", (indent + 1) * 4, "");
        test_print_policy_decision(&entry->decision);
}

static void test_print_policy_xmit_list(CList *policy, const char *name, unsigned int indent) {
        PolicyXmitEntry *entry;

        if (c_list_is_empty(policy))
                return;

        fprintf(stderr, "%*s%s:\n", indent * 4, "", name);

        c_list_for_each_entry(entry, policy, policy_link)
                test_print_policy_xmit_entry(entry, indent + 1);
}

static void test_print_policy_xmit(PolicyXmit *policy, const char *name, unsigned int indent) {
        PolicyXmitByName *entry;

        if (policy_xmit_is_empty(policy))
                return;

        fprintf(stderr, "%*s%s:\n", indent * 4, "", name);
        test_print_policy_xmit_list(&policy->wildcard_entry_list, "*", indent + 1);

        c_rbtree_for_each_entry(entry, &policy->policy_by_name_tree, policy_node)
                test_print_policy_xmit_list(&entry->entry_list, entry->name, indent + 1);
}

static void test_print_policy(Policy *policy, const char *name, int num, unsigned int indent) {
        if (policy_is_empty(policy))
                return;

        if (name)
                fprintf(stderr, "%*s%s:\n", indent * 4, "", name);
        else
                fprintf(stderr, "%*s%d:\n", indent * 4, "", num);

        test_print_policy_own(&policy->policy_own, indent + 1);
        test_print_policy_xmit(&policy->policy_send, "SEND", indent + 1);
        test_print_policy_xmit(&policy->policy_receive, "RECEIVE", indent + 1);
}

static void test_print_policy_registry_tree(CRBTree *policy, const char *name, unsigned int indent) {
        Policy *entry;

        if (c_rbtree_is_empty(policy))
                return;

        fprintf(stderr, "%*s%s:\n", indent * 4, "", name);

        c_rbtree_for_each_entry(entry, policy, registry_node)
                test_print_policy(entry, NULL, entry->uid, indent + 1);
}

static void test_print_policy_registry(PolicyParserRegistry *registry) {
        test_print_policy_connect(&registry->registry.policy_connect, 0);
        test_print_policy(&registry->default_policy, "DEFAULT", 0, 0);
        test_print_policy_registry_tree(&registry->registry.gid_policy_tree, "GROUP", 0);
        test_print_policy_registry_tree(&registry->registry.uid_policy_tree, "USER", 0);
        test_print_policy(&registry->console_policy, "NOT AT CONSOLE", 0, 0);
        test_print_policy(&registry->mandatory_policy, "MANDATORY", 0, 0);
}

static void test_basic(void) {
        _c_cleanup_(policy_parser_registry_deinit) PolicyParserRegistry registry = POLICY_PARSER_REGISTRY_NULL(registry);
        int r;

        r = policy_parser_registry_init(&registry);
        assert(!r);

        r = policy_parser_registry_append_file(&registry, "/usr/share/dbus-1/system.conf", NULL);
        assert(!r);

        test_print_policy_registry(&registry);
}

int main(int argc, char **argv) {
        test_basic();
}
