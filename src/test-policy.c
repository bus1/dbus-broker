/*
 * Test Policy
 */

#include <c-macro.h>
#include <stdlib.h>
#include "dbus/protocol.h"
#include "policy.h"

static void test_print_policy_decision(PolicyDecision *decision) {
        fprintf(stderr, "%s (%lu)\n", decision->deny ? "deny" : "allow", decision->priority);
}

static void test_print_connection_policy_tree(CRBTree *policy, const char *name, unsigned int indent) {
        ConnectionPolicyEntry *entry;

        if (c_rbtree_is_empty(policy))
                return;

        fprintf(stderr, "%*s%s:\n", indent * 4, "", name);

        c_rbtree_for_each_entry(entry, policy, rb) {
                fprintf(stderr, "%*s%u: ", (indent + 1) * 4, "", entry->uid);
                test_print_policy_decision(&entry->decision);
        }
}

static void test_print_connection_policy(ConnectionPolicy *policy, unsigned int indent) {
        if (connection_policy_is_empty(policy))
                return;

        fprintf(stderr, "%*sCONNECTION:\n", indent * 4, "");

        if (!policy_decision_is_default(&policy->wildcard)) {
                fprintf(stderr, "%*s*: ", (indent + 1) * 4, "");
                test_print_policy_decision(&policy->wildcard);
        }
        test_print_connection_policy_tree(&policy->gid_tree, "GID", indent + 1);
        test_print_connection_policy_tree(&policy->gid_tree, "UID", indent + 1);
}

static void test_print_ownership_policy_tree(CRBTree *policy, const char *suffix, unsigned int indent) {
        OwnershipPolicyEntry *entry;

        c_rbtree_for_each_entry(entry, policy, rb) {
                fprintf(stderr, "%*s%s%s: ", indent * 4, "", entry->name, suffix ?: "");
                test_print_policy_decision(&entry->decision);
        }
}

static void test_print_ownership_policy(OwnershipPolicy *policy, unsigned int indent) {
        if (ownership_policy_is_empty(policy))
                return;

        fprintf(stderr, "%*sOWN:\n", indent * 4, "");

        if (!policy_decision_is_default(&policy->wildcard)) {
                fprintf(stderr, "%*s*: ", (indent + 1) * 4, "");
                test_print_policy_decision(&policy->wildcard);
        }
        test_print_ownership_policy_tree(&policy->names, NULL, indent + 1);
        test_print_ownership_policy_tree(&policy->prefixes, ".*", indent + 1);
}

static void test_print_transmission_policy_entry(TransmissionPolicyEntry *entry, unsigned int indent) {
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

static void test_print_transmission_policy_list(CList *policy, const char *name, unsigned int indent) {
        TransmissionPolicyEntry *entry;

        if (c_list_is_empty(policy))
                return;

        fprintf(stderr, "%*s%s:\n", indent * 4, "", name);

        c_list_for_each_entry(entry, policy, policy_link)
                test_print_transmission_policy_entry(entry, indent + 1);
}

static void test_print_transmission_policy(TransmissionPolicy *policy, const char *name, unsigned int indent) {
        TransmissionPolicyByName *entry;

        if (transmission_policy_is_empty(policy))
                return;

        fprintf(stderr, "%*s%s:\n", indent * 4, "", name);
        test_print_transmission_policy_list(&policy->wildcard_entry_list, "*", indent + 1);

        c_rbtree_for_each_entry(entry, &policy->policy_by_name_tree, policy_node)
                test_print_transmission_policy_list(&entry->entry_list, entry->name, indent + 1);
}

static void test_print_policy(Policy *policy, const char *name, int num, unsigned int indent) {
        if (policy_is_empty(policy))
                return;

        if (name)
                fprintf(stderr, "%*s%s:\n", indent * 4, "", name);
        else
                fprintf(stderr, "%*s%d:\n", indent * 4, "", num);

        test_print_ownership_policy(&policy->ownership_policy, indent + 1);
        test_print_transmission_policy(&policy->send_policy, "SEND", indent + 1);
        test_print_transmission_policy(&policy->receive_policy, "RECEIVE", indent + 1);
}

static void test_print_policy_registry_tree(CRBTree *policy, const char *name, unsigned int indent) {
        Policy *entry;

        if (c_rbtree_is_empty(policy))
                return;

        fprintf(stderr, "%*s%s:\n", indent * 4, "", name);

        c_rbtree_for_each_entry(entry, policy, registry_node)
                test_print_policy(entry, NULL, entry->uid, indent + 1);
}

static void test_print_policy_registry(PolicyRegistry *registry) {
        test_print_connection_policy(&registry->connection_policy, 0);
        test_print_policy(&registry->default_policy, "DEFAULT", 0, 0);
        test_print_policy_registry_tree(&registry->gid_policy_tree, "GROUP", 0);
        test_print_policy_registry_tree(&registry->uid_policy_tree, "USER", 0);
        test_print_policy(&registry->at_console_policy, "AT CONSOLE", 0, 0);
        test_print_policy(&registry->not_at_console_policy, "NOT AT CONSOLE", 0, 0);
}

static void test_basic() {
        _c_cleanup_(policy_registry_deinit) PolicyRegistry registry = POLICY_REGISTRY_INIT(registry);
        int r;

        r = policy_registry_from_file(&registry, "/usr/share/dbus-1/system.conf", NULL);
        assert(!r);

        test_print_policy_registry(&registry);
}

int main(int argc, char **argv) {
        test_basic();
}
