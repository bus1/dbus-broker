/*
 * D-Bus Policy Converter
 */

#include <c-list.h>
#include <c-macro.h>
#include <c-rbtree.h>
#include <stdlib.h>
#include <systemd/sd-bus.h>
#include "dbus/protocol.h"
#include "launch/config.h"
#include "launch/policy.h"
#include "util/error.h"

/**
 * policy_record_new_connect() - XXX
 */
int policy_record_new_connect(PolicyRecord **recordp) {
        _c_cleanup_(policy_record_freep) PolicyRecord *record = NULL;

        record = calloc(1, sizeof(*record));
        if (!record)
                return error_origin(-ENOMEM);

        *record = (PolicyRecord)POLICY_RECORD_INIT_CONNECT(*record);

        *recordp = record;
        record = NULL;
        return 0;
}

/**
 * policy_record_new_own() - XXX
 */
int policy_record_new_own(PolicyRecord **recordp) {
        _c_cleanup_(policy_record_freep) PolicyRecord *record = NULL;

        record = calloc(1, sizeof(*record));
        if (!record)
                return error_origin(-ENOMEM);

        *record = (PolicyRecord)POLICY_RECORD_INIT_OWN(*record);

        *recordp = record;
        record = NULL;
        return 0;
}

/**
 * policy_record_new_xmit() - XXX
 */
int policy_record_new_xmit(PolicyRecord **recordp) {
        _c_cleanup_(policy_record_freep) PolicyRecord *record = NULL;

        record = calloc(1, sizeof(*record));
        if (!record)
                return error_origin(-ENOMEM);

        *record = (PolicyRecord)POLICY_RECORD_INIT_XMIT(*record);

        *recordp = record;
        record = NULL;
        return 0;
}

/**
 * policy_record_new_selinux() - XXX
 */
int policy_record_new_selinux(PolicyRecord **recordp) {
        _c_cleanup_(policy_record_freep) PolicyRecord *record = NULL;

        record = calloc(1, sizeof(*record));
        if (!record)
                return error_origin(-ENOMEM);

        *record = (PolicyRecord)POLICY_RECORD_INIT_SELINUX(*record);

        *recordp = record;
        record = NULL;
        return 0;
}

/**
 * policy_record_free() - XXX
 */
PolicyRecord *policy_record_free(PolicyRecord *record) {
        if (!record)
                return NULL;

        c_list_unlink_init(&record->link);
        free(record);

        return NULL;
}

static void policy_record_xmit_trim(PolicyRecord *record) {
        if (record->xmit.name && !strcmp(record->xmit.name, "*"))
                record->xmit.name = NULL;
        if (record->xmit.path && !strcmp(record->xmit.path, "*"))
                record->xmit.path = NULL;
        if (record->xmit.interface && !strcmp(record->xmit.interface, "*"))
                record->xmit.interface = NULL;
        if (record->xmit.member && !strcmp(record->xmit.member, "*"))
                record->xmit.member = NULL;
}

static int policy_node_compare(CRBTree *t, void *k, CRBNode *n) {
        PolicyNode *node = c_container_of(n, PolicyNode, policy_node);
        PolicyNodeIndex *index = k;

        if (index->uidgid_start < node->index.uidgid_start)
                return -1;
        else if (index->uidgid_start > node->index.uidgid_start)
                return 1;
        else if (index->uidgid_end < node->index.uidgid_end)
                return -1;
        else if (index->uidgid_end > node->index.uidgid_end)
                return 1;
        else
                return 0;
}

static PolicyNode *policy_node_free(PolicyNode *node) {
        PolicyRecord *record;

        if (!node)
                return NULL;

        while ((record = c_list_first_entry(&node->recv_list, PolicyRecord, link)))
                policy_record_free(record);
        while ((record = c_list_first_entry(&node->send_list, PolicyRecord, link)))
                policy_record_free(record);
        while ((record = c_list_first_entry(&node->own_list, PolicyRecord, link)))
                policy_record_free(record);
        while ((record = c_list_first_entry(&node->connect_list, PolicyRecord, link)))
                policy_record_free(record);

        c_rbnode_unlink_init(&node->policy_node);
        free(node);

        return NULL;
}

C_DEFINE_CLEANUP(PolicyNode *, policy_node_free);

static int policy_node_new(PolicyNode **nodep, uint32_t uidgid_start, uint32_t uidgid_end) {
        _c_cleanup_(policy_node_freep) PolicyNode *node = NULL;

        node = calloc(1, sizeof(*node));
        if (!node)
                return error_origin(-ENOMEM);

        *node = (PolicyNode)POLICY_NODE_NULL(*node);
        node->index.uidgid_start = uidgid_start;
        node->index.uidgid_end = uidgid_end;

        *nodep = node;
        node = NULL;
        return 0;
}

/**
 * policy_init() - XXX
 */
void policy_init(Policy *policy) {
        *policy = (Policy)POLICY_INIT(*policy);
}

/**
 * policy_deinit() - XXX
 */
void policy_deinit(Policy *policy) {
        PolicyNode *node, *t_node;
        PolicyRecord *record;

        while ((record = c_list_first_entry(&policy->selinux_list, PolicyRecord, link)))
                policy_record_free(record);

        c_rbtree_for_each_entry_safe_postorder_unlink(node, t_node, &policy->gid_tree, policy_node)
                policy_node_free(node);
        c_rbtree_for_each_entry_safe_postorder_unlink(node, t_node, &policy->uid_tree, policy_node)
                policy_node_free(node);

        while ((record = c_list_first_entry(&policy->recv_default, PolicyRecord, link)))
                policy_record_free(record);
        while ((record = c_list_first_entry(&policy->send_default, PolicyRecord, link)))
                policy_record_free(record);
        while ((record = c_list_first_entry(&policy->own_default, PolicyRecord, link)))
                policy_record_free(record);
        while ((record = c_list_first_entry(&policy->connect_default, PolicyRecord, link)))
                policy_record_free(record);
}

static int policy_at_uidgid(CRBTree *tree, PolicyNode **nodep, uint32_t uidgid_start, uint32_t uidgid_end) {
        CRBNode *parent, **slot;
        PolicyNode *node;
        PolicyNodeIndex index = {
                .uidgid_start = uidgid_start,
                .uidgid_end = uidgid_end,
        };
        int r;

        slot = c_rbtree_find_slot(tree,
                                  policy_node_compare,
                                  &index,
                                  &parent);
        if (slot) {
                r = policy_node_new(&node, uidgid_start, uidgid_end);
                if (r)
                        return error_trace(r);

                c_rbtree_add(tree, parent, slot, &node->policy_node);
        } else {
                node = c_container_of(parent, PolicyNode, policy_node);
        }

        *nodep = node;
        node = NULL;
        return 0;
}

static int policy_at_systemuid(Policy *policy, PolicyNode **nodep) {
        return policy_at_uidgid(&policy->uid_tree, nodep, 0, SYSTEMUIDMAX);
}

static int policy_at_nonsystemuid(Policy *policy, PolicyNode **nodep) {
        return policy_at_uidgid(&policy->uid_tree, nodep, SYSTEMUIDMAX + 1, -1);
}

static int policy_at_uid(Policy *policy, PolicyNode **nodep, uint32_t uid) {
        return policy_at_uidgid(&policy->uid_tree, nodep, uid, uid);
}

static int policy_at_gid(Policy *policy, PolicyNode **nodep, uint32_t gid) {
        return policy_at_uidgid(&policy->gid_tree, nodep, gid, gid);
}

static void policy_import_verdict(Policy *policy,
                                  PolicyRecord *record,
                                  ConfigNode *cnode) {
        assert(cnode->parent);
        assert(cnode->parent->type == CONFIG_NODE_POLICY);
        assert(cnode->parent->policy.context);
        assert(cnode->parent->policy.context < _CONFIG_POLICY_N);

        record->verdict = (cnode->type == CONFIG_NODE_ALLOW);
        record->priority = UINT64_MAX / _CONFIG_POLICY_N *
                           cnode->parent->policy.context +
                           ++policy->i_priority;
}

static int policy_import_connect_self(Policy *policy) {
        _c_cleanup_(policy_record_freep) PolicyRecord *record = NULL;
        PolicyNode *node;
        int r;

        /*
         * According to dbus-daemon(1), the default policy for the
         * controller-UID is ALLOW, as opposed to the default policy for any
         * other UID which is DENY.
         * Since the broker has a DENY-ALL as default, we need to fake a
         * fallback policy here that allows the calling uid to connect.
         */

        r = policy_record_new_connect(&record);
        if (r)
                return error_trace(r);

        record->verdict = true;
        record->priority = ++policy->i_priority;

        r = policy_at_uid(policy, &node, getuid());
        if (r)
                return error_trace(r);

        c_list_link_tail(&node->connect_list, &record->link);

        record = NULL;
        return 0;
}

static int policy_import_connect(Policy *policy, ConfigNode *cnode) {
        _c_cleanup_(policy_record_freep) PolicyRecord *record = NULL;
        PolicyNode *node;
        int r;

        assert(cnode->parent);
        assert(cnode->parent->type == CONFIG_NODE_POLICY);

        if ((cnode->allow_deny.user == cnode->allow_deny.group) ||
            cnode->allow_deny.own ||
            cnode->allow_deny.own_prefix ||
            cnode->allow_deny.send_interface ||
            cnode->allow_deny.send_interface ||
            cnode->allow_deny.send_member ||
            cnode->allow_deny.send_error ||
            cnode->allow_deny.send_destination ||
            cnode->allow_deny.send_path ||
            cnode->allow_deny.send_type ||
            cnode->allow_deny.send_requested_reply ||
            cnode->allow_deny.recv_interface ||
            cnode->allow_deny.recv_member ||
            cnode->allow_deny.recv_error ||
            cnode->allow_deny.recv_sender ||
            cnode->allow_deny.recv_path ||
            cnode->allow_deny.recv_type ||
            cnode->allow_deny.recv_requested_reply) {
                fprintf(stderr, "Invalid policy attribute combination in %s +%lu\n",
                        cnode->file, cnode->lineno);
                return 0;
        }

        if (cnode->parent->policy.context == CONFIG_POLICY_USER ||
            cnode->parent->policy.context == CONFIG_POLICY_GROUP) {
                fprintf(stderr, "Connection policy not allowed in user/group context in %s +%lu\n",
                        cnode->file, cnode->lineno);
                return 0;
        }

        r = policy_record_new_connect(&record);
        if (r)
                return error_trace(r);

        policy_import_verdict(policy, record, cnode);

        if (cnode->allow_deny.user && cnode->allow_deny.uid != (uint32_t)-1) {
                r = policy_at_uid(policy, &node, cnode->allow_deny.uid);
                if (r)
                        return error_trace(r);

                c_list_link_tail(&node->connect_list, &record->link);
        } else if (cnode->allow_deny.group && cnode->allow_deny.gid != (uint32_t)-1) {
                r = policy_at_gid(policy, &node, cnode->allow_deny.uid);
                if (r)
                        return error_trace(r);

                c_list_link_tail(&node->connect_list, &record->link);
        } else {
                c_list_link_tail(&policy->connect_default, &record->link);
        }

        record = NULL;
        return 0;
}

static int policy_import_own(Policy *policy, ConfigNode *cnode) {
        _c_cleanup_(policy_record_freep) PolicyRecord *record = NULL;
        PolicyNode *node;
        int r;

        assert(cnode->parent);
        assert(cnode->parent->type == CONFIG_NODE_POLICY);

        if ((!cnode->allow_deny.own == !cnode->allow_deny.own_prefix) ||
            cnode->allow_deny.user ||
            cnode->allow_deny.group ||
            cnode->allow_deny.send_interface ||
            cnode->allow_deny.send_interface ||
            cnode->allow_deny.send_member ||
            cnode->allow_deny.send_error ||
            cnode->allow_deny.send_destination ||
            cnode->allow_deny.send_path ||
            cnode->allow_deny.send_type ||
            cnode->allow_deny.send_requested_reply ||
            cnode->allow_deny.recv_interface ||
            cnode->allow_deny.recv_member ||
            cnode->allow_deny.recv_error ||
            cnode->allow_deny.recv_sender ||
            cnode->allow_deny.recv_path ||
            cnode->allow_deny.recv_type ||
            cnode->allow_deny.recv_requested_reply) {
                fprintf(stderr, "Invalid policy attribute combination in %s +%lu\n",
                        cnode->file, cnode->lineno);
                return 0;
        }

        r = policy_record_new_own(&record);
        if (r)
                return error_trace(r);

        policy_import_verdict(policy, record, cnode);

        if (cnode->allow_deny.own) {
                if (!strcmp(cnode->allow_deny.own, "*")) {
                        record->own.prefix = true;
                        record->own.name = "";
                } else {
                        record->own.prefix = false;
                        record->own.name = cnode->allow_deny.own;
                }
        } else {
                record->own.prefix = true;
                record->own.name = cnode->allow_deny.own_prefix;
        }

        if (cnode->parent->policy.context == CONFIG_POLICY_USER) {
                r = policy_at_uid(policy, &node, cnode->parent->policy.id);
                if (r)
                        return error_trace(r);

                c_list_link_tail(&node->own_list, &record->link);
        } else if (cnode->parent->policy.context == CONFIG_POLICY_NO_CONSOLE) {
                r = policy_at_systemuid(policy, &node);
                if (r)
                        return error_trace(r);

                c_list_link_tail(&node->own_list, &record->link);
        } else if (cnode->parent->policy.context == CONFIG_POLICY_AT_CONSOLE) {
                r = policy_at_nonsystemuid(policy, &node);
                if (r)
                        return error_trace(r);

                c_list_link_tail(&node->own_list, &record->link);
        } else if (cnode->parent->policy.context == CONFIG_POLICY_GROUP) {
                r = policy_at_gid(policy, &node, cnode->parent->policy.id);
                if (r)
                        return error_trace(r);

                c_list_link_tail(&node->own_list, &record->link);
        } else {
                c_list_link_tail(&policy->own_default, &record->link);
        }

        record = NULL;
        return 0;
}

static int policy_import_send(Policy *policy, ConfigNode *cnode) {
        _c_cleanup_(policy_record_freep) PolicyRecord *record = NULL;
        PolicyNode *node;
        int r;

        assert(cnode->parent);
        assert(cnode->parent->type == CONFIG_NODE_POLICY);

        if (cnode->allow_deny.user ||
            cnode->allow_deny.group ||
            cnode->allow_deny.own ||
            cnode->allow_deny.own_prefix ||
            cnode->allow_deny.recv_interface ||
            cnode->allow_deny.recv_member ||
            cnode->allow_deny.recv_error ||
            cnode->allow_deny.recv_sender ||
            cnode->allow_deny.recv_path ||
            cnode->allow_deny.recv_type ||
            cnode->allow_deny.recv_requested_reply) {
                fprintf(stderr, "Invalid policy attribute combination in %s +%lu\n",
                        cnode->file, cnode->lineno);
                return 0;
        }

        if (cnode->allow_deny.send_type == DBUS_MESSAGE_TYPE_METHOD_RETURN ||
            cnode->allow_deny.send_type == DBUS_MESSAGE_TYPE_ERROR) {
                fprintf(stderr, "Reply/Error policy in %s +%lu: Explicit policies on replies and errors are deprecated and ignored\n",
                        cnode->file, cnode->lineno);
                return 0;
        }

        if (cnode->allow_deny.send_error ||
            cnode->allow_deny.send_requested_reply)
                fprintf(stderr, "Expected-reply/Error policy match in %s +%lu: Those attributes are deprecated and ignored\n",
                        cnode->file, cnode->lineno);

        r = policy_record_new_xmit(&record);
        if (r)
                return error_trace(r);

        policy_import_verdict(policy, record, cnode);

        record->xmit.name = cnode->allow_deny.send_destination;
        record->xmit.path = cnode->allow_deny.send_path;
        record->xmit.interface = cnode->allow_deny.send_interface;
        record->xmit.member = cnode->allow_deny.send_member;
        record->xmit.type = cnode->allow_deny.send_type;
        record->xmit.eavesdrop = (cnode->allow_deny.eavesdrop == CONFIG_TRISTATE_YES);
        policy_record_xmit_trim(record);

        if (cnode->parent->policy.context == CONFIG_POLICY_USER) {
                r = policy_at_uid(policy, &node, cnode->parent->policy.id);
                if (r)
                        return error_trace(r);

                c_list_link_tail(&node->send_list, &record->link);
        } else if (cnode->parent->policy.context == CONFIG_POLICY_NO_CONSOLE) {
                r = policy_at_systemuid(policy, &node);
                if (r)
                        return error_trace(r);

                c_list_link_tail(&node->send_list, &record->link);
        } else if (cnode->parent->policy.context == CONFIG_POLICY_AT_CONSOLE) {
                r = policy_at_nonsystemuid(policy, &node);
                if (r)
                        return error_trace(r);

                c_list_link_tail(&node->send_list, &record->link);
        } else if (cnode->parent->policy.context == CONFIG_POLICY_GROUP) {
                r = policy_at_gid(policy, &node, cnode->parent->policy.id);
                if (r)
                        return error_trace(r);

                c_list_link_tail(&node->send_list, &record->link);
        } else {
                c_list_link_tail(&policy->send_default, &record->link);
        }

        record = NULL;
        return 0;
}

static int policy_import_recv(Policy *policy, ConfigNode *cnode) {
        _c_cleanup_(policy_record_freep) PolicyRecord *record = NULL;
        PolicyNode *node;
        int r;

        assert(cnode->parent);
        assert(cnode->parent->type == CONFIG_NODE_POLICY);

        if (cnode->allow_deny.user ||
            cnode->allow_deny.group ||
            cnode->allow_deny.own ||
            cnode->allow_deny.own_prefix ||
            cnode->allow_deny.send_interface ||
            cnode->allow_deny.send_member ||
            cnode->allow_deny.send_error ||
            cnode->allow_deny.send_destination ||
            cnode->allow_deny.send_path ||
            cnode->allow_deny.send_type ||
            cnode->allow_deny.send_requested_reply) {
                fprintf(stderr, "Invalid policy attribute combination in %s +%lu\n",
                        cnode->file, cnode->lineno);
                return 0;
        }

        if (cnode->allow_deny.recv_type == DBUS_MESSAGE_TYPE_METHOD_RETURN ||
            cnode->allow_deny.recv_type == DBUS_MESSAGE_TYPE_ERROR) {
                fprintf(stderr, "Reply/Error policy in %s +%lu: Explicit policies on replies and errors are deprecated and ignored\n",
                        cnode->file, cnode->lineno);
                return 0;
        }

        if (cnode->allow_deny.recv_error ||
            cnode->allow_deny.recv_requested_reply)
                fprintf(stderr, "Expected-reply/Error policy match in %s +%lu: Those attributes are deprecated and ignored\n",
                        cnode->file, cnode->lineno);

        r = policy_record_new_xmit(&record);
        if (r)
                return error_trace(r);

        policy_import_verdict(policy, record, cnode);

        record->xmit.name = cnode->allow_deny.recv_sender;
        record->xmit.path = cnode->allow_deny.recv_path;
        record->xmit.interface = cnode->allow_deny.recv_interface;
        record->xmit.member = cnode->allow_deny.recv_member;
        record->xmit.type = cnode->allow_deny.recv_type;
        record->xmit.eavesdrop = (cnode->allow_deny.eavesdrop == CONFIG_TRISTATE_YES);
        policy_record_xmit_trim(record);

        if (cnode->parent->policy.context == CONFIG_POLICY_USER) {
                r = policy_at_uid(policy, &node, cnode->parent->policy.id);
                if (r)
                        return error_trace(r);

                c_list_link_tail(&node->recv_list, &record->link);
        } else if (cnode->parent->policy.context == CONFIG_POLICY_NO_CONSOLE) {
                r = policy_at_systemuid(policy, &node);
                if (r)
                        return error_trace(r);

                c_list_link_tail(&node->recv_list, &record->link);
        } else if (cnode->parent->policy.context == CONFIG_POLICY_AT_CONSOLE) {
                r = policy_at_nonsystemuid(policy, &node);
                if (r)
                        return error_trace(r);

                c_list_link_tail(&node->recv_list, &record->link);
        } else if (cnode->parent->policy.context == CONFIG_POLICY_GROUP) {
                r = policy_at_gid(policy, &node, cnode->parent->policy.id);
                if (r)
                        return error_trace(r);

                c_list_link_tail(&node->recv_list, &record->link);
        } else {
                c_list_link_tail(&policy->recv_default, &record->link);
        }

        record = NULL;
        return 0;
}

static int policy_import_selinux(Policy *policy, ConfigNode *cnode) {
        _c_cleanup_(policy_record_freep) PolicyRecord *record = NULL;
        int r;

        assert(cnode->parent);
        assert(cnode->parent->type == CONFIG_NODE_SELINUX);

        if (!cnode->associate.own ||
            !cnode->associate.context) {
                fprintf(stderr, "Invalid policy attribute combination in %s +%lu\n",
                        cnode->file, cnode->lineno);
                return 0;
        }

        r = policy_record_new_own(&record);
        if (r)
                return error_trace(r);

        policy_import_verdict(policy, record, cnode);

        record->selinux.name = cnode->associate.own;
        record->selinux.context = cnode->associate.context;

        c_list_link_tail(&policy->selinux_list, &record->link);

        record = NULL;
        return 0;
}

/**
 * policy_import() - XXX
 */
int policy_import(Policy *policy, ConfigRoot *root) {
        ConfigNode *i_cnode;
        int r;

        r = policy_import_connect_self(policy);
        if (r)
                return error_trace(r);

        c_list_for_each_entry(i_cnode, &root->node_list, root_link) {
                if (i_cnode->type == CONFIG_NODE_ASSOCIATE) {
                        r = policy_import_selinux(policy, i_cnode);
                        if (r)
                                return error_trace(r);
                        continue;
                }

                if (i_cnode->type != CONFIG_NODE_ALLOW &&
                    i_cnode->type != CONFIG_NODE_DENY)
                        continue;

                if (!i_cnode->parent ||
                    i_cnode->parent->type != CONFIG_NODE_POLICY ||
                    !i_cnode->parent->policy.context) {
                        fprintf(stderr, "Policy record without policy context in %s +%lu\n",
                                i_cnode->file, i_cnode->lineno);
                        continue;
                }

                if (i_cnode->allow_deny.user ||
                    i_cnode->allow_deny.group) {
                        r = policy_import_connect(policy, i_cnode);
                        if (r)
                                return error_trace(r);
                } else if (i_cnode->allow_deny.own ||
                           i_cnode->allow_deny.own_prefix) {
                        r = policy_import_own(policy, i_cnode);
                        if (r)
                                return error_trace(r);
                } else if (i_cnode->allow_deny.send_interface ||
                           i_cnode->allow_deny.send_member ||
                           i_cnode->allow_deny.send_error ||
                           i_cnode->allow_deny.send_destination ||
                           i_cnode->allow_deny.send_path ||
                           i_cnode->allow_deny.send_type ||
                           i_cnode->allow_deny.send_requested_reply) {
                        r = policy_import_send(policy, i_cnode);
                        if (r)
                                return error_trace(r);
                } else if (i_cnode->allow_deny.recv_interface ||
                           i_cnode->allow_deny.recv_member ||
                           i_cnode->allow_deny.recv_error ||
                           i_cnode->allow_deny.recv_sender ||
                           i_cnode->allow_deny.recv_path ||
                           i_cnode->allow_deny.recv_type ||
                           i_cnode->allow_deny.recv_requested_reply ||
                           i_cnode->allow_deny.eavesdrop) {
                        r = policy_import_recv(policy, i_cnode);
                        if (r)
                                return error_trace(r);
                } else {
                        fprintf(stderr, "Invalid policy without defining attributes in %s +%lu\n",
                                i_cnode->file, i_cnode->lineno);
                }
        }

        return 0;
}

static PolicyRecord *policy_list_find_top(CList *list) {
        PolicyRecord *i_record, *top_record;

        top_record = NULL;
        c_list_for_each_entry(i_record, list, link)
                if (!top_record || i_record->priority > top_record->priority)
                        top_record = i_record;

        return top_record;
}

static void policy_list_shrink(CList *list, PolicyRecord *keep) {
        PolicyRecord *i_record, *t_record;

        c_list_for_each_entry_safe(i_record, t_record, list, link)
                if (i_record != keep)
                        policy_record_free(i_record);
}

static void policy_optimize_connect(Policy *policy) {
        PolicyRecord *top_default, *top;
        PolicyNode *i_node;

        /*
         * In case of CONNECT policies, all information we have is whether or
         * not a given UID or GID is allowed to connect. There is no further
         * filters, hence we can reduce the policy decision for each UID (or
         * GID) to a single boolean by throwing away anything but the highest
         * priority verdict.
         *
         * Furthermore, we can throw out UID or GID entries if the default
         * entry has a higher priority.
         */

        /* shrink @connect_default down to 1 entry */
        top_default = policy_list_find_top(&policy->connect_default);
        policy_list_shrink(&policy->connect_default, top_default);

        /* shrink each uid-map down to 1 entry (or 0 if below @top_default) */
        c_rbtree_for_each_entry(i_node, &policy->uid_tree, policy_node) {
                top = policy_list_find_top(&i_node->connect_list);
                if (top && top_default && top->priority <= top_default->priority)
                        top = NULL;
                policy_list_shrink(&i_node->connect_list, top);
        }

        /* shrink each gid-map down to 1 entry (or 0 if below @top_default) */
        c_rbtree_for_each_entry(i_node, &policy->gid_tree, policy_node) {
                top = policy_list_find_top(&i_node->connect_list);
                if (top && top_default && top->priority <= top_default->priority)
                        top = NULL;
                policy_list_shrink(&i_node->connect_list, top);
        }
}

static void policy_optimize_trim(Policy *policy) {
        PolicyNode *node, *t_node;

        /*
         * The optimizations might have dropped entries that are redundant or
         * have no effect. Hence, lets trim our policy and drop all the uid/gid
         * nodes that no longer have any records.
         */

        c_rbtree_for_each_entry_safe(node, t_node, &policy->uid_tree, policy_node)
                if (c_list_is_empty(&node->connect_list) &&
                    c_list_is_empty(&node->own_list) &&
                    c_list_is_empty(&node->send_list) &&
                    c_list_is_empty(&node->recv_list))
                        policy_node_free(node);

        c_rbtree_for_each_entry_safe(node, t_node, &policy->gid_tree, policy_node)
                if (c_list_is_empty(&node->connect_list) &&
                    c_list_is_empty(&node->own_list) &&
                    c_list_is_empty(&node->send_list) &&
                    c_list_is_empty(&node->recv_list))
                        policy_node_free(node);
}

/**
 * policy_optimize() - XXX
 */
void policy_optimize(Policy *policy) {
        /*
         * XXX: There are many more optimizations possible. Lets figure out
         *      which of those are worth it, and then implement them.
         */

        policy_optimize_connect(policy);
        policy_optimize_trim(policy);
}

static int policy_export_connect(Policy *policy, CList *default_list, CList *specific_list, sd_bus_message *m) {
        PolicyRecord *top = NULL;
        int r;

        if (specific_list) {
                top = c_list_first_entry(specific_list, PolicyRecord, link);
                /* list must be empty or singular */
                assert(top == c_list_last_entry(specific_list, PolicyRecord, link));
        }

        if (!top && default_list) {
                top = c_list_first_entry(default_list, PolicyRecord, link);
                /* list must be empty or singular */
                assert(top == c_list_last_entry(default_list, PolicyRecord, link));
        }

        if (top)
                r = sd_bus_message_append(m, "bt", top->verdict, top->priority);
        else
                r = sd_bus_message_append(m, "bt", false, UINT64_C(1));
        if (r < 0)
                return error_origin(r);

        return 0;
}

static int policy_export_own(Policy *policy, CList *list1, CList *list2, sd_bus_message *m) {
        PolicyRecord *i_record;
        int r;

        r = sd_bus_message_open_container(m, 'a', "(btbs)");
        if (r < 0)
                return error_origin(r);

        if (list1) {
                c_list_for_each_entry(i_record, list1, link) {
                        r = sd_bus_message_append(m,
                                                  "(btbs)",
                                                  i_record->verdict,
                                                  i_record->priority,
                                                  i_record->own.prefix,
                                                  i_record->own.name);
                        if (r < 0)
                                return error_origin(r);
                }
        }

        if (list2) {
                c_list_for_each_entry(i_record, list2, link) {
                        r = sd_bus_message_append(m,
                                                  "(btbs)",
                                                  i_record->verdict,
                                                  i_record->priority,
                                                  i_record->own.prefix,
                                                  i_record->own.name);
                        if (r < 0)
                                return error_origin(r);
                }
        }

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return error_origin(r);

        return 0;
}

static int policy_export_xmit(Policy *policy, CList *list1, CList *list2, sd_bus_message *m) {
        PolicyRecord *i_record;
        int r;

        r = sd_bus_message_open_container(m, 'a', "(btssssub)");
        if (r < 0)
                return error_origin(r);

        if (list1) {
                c_list_for_each_entry(i_record, list1, link) {
                        r = sd_bus_message_append(m,
                                                  "(btssssub)",
                                                  i_record->verdict,
                                                  i_record->priority,
                                                  i_record->xmit.name,
                                                  i_record->xmit.path,
                                                  i_record->xmit.interface,
                                                  i_record->xmit.member,
                                                  i_record->xmit.type,
                                                  i_record->xmit.eavesdrop);
                        if (r < 0)
                                return error_origin(r);
                }
        }

        if (list2) {
                c_list_for_each_entry(i_record, list2, link) {
                        r = sd_bus_message_append(m,
                                                  "(btssssub)",
                                                  i_record->verdict,
                                                  i_record->priority,
                                                  i_record->xmit.name,
                                                  i_record->xmit.path,
                                                  i_record->xmit.interface,
                                                  i_record->xmit.member,
                                                  i_record->xmit.type,
                                                  i_record->xmit.eavesdrop);
                        if (r < 0)
                                return error_origin(r);
                }
        }

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return error_origin(r);

        return 0;
}

#define POLICY_T_BATCH                                                          \
                "bt"                                                            \
                "a(btbs)"                                                       \
                "a(btssssub)"                                                   \
                "a(btssssub)"

#define POLICY_T                                                                \
                "(" POLICY_T_BATCH ")"                                          \
                "a(uu(" POLICY_T_BATCH "))"                                     \
                "a(u(" POLICY_T_BATCH "))"                                      \
                "a(ss)"

/**
 * policy_export() - XXX
 */
int policy_export(Policy *policy, sd_bus_message *m) {
        PolicyNode *node;
        PolicyRecord *i_record;
        int r;

        r = sd_bus_message_open_container(m, 'v', "(" POLICY_T ")");
        if (r < 0)
                return error_origin(r);

        r = sd_bus_message_open_container(m, 'r', POLICY_T);
        if (r < 0)
                return error_origin(r);

        r = sd_bus_message_open_container(m, 'r', POLICY_T_BATCH);
        if (r < 0)
                return error_origin(r);

        r = policy_export_connect(policy, &policy->connect_default, NULL, m);
        r = r ?: policy_export_own(policy, &policy->own_default, NULL, m);
        r = r ?: policy_export_xmit(policy, &policy->send_default, NULL, m);
        r = r ?: policy_export_xmit(policy, &policy->recv_default, NULL, m);
        if (r)
                return error_trace(r);

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return error_origin(r);

        r = sd_bus_message_open_container(m, 'a', "(uu(" POLICY_T_BATCH "))");
        if (r < 0)
                return error_origin(r);

        c_rbtree_for_each_entry(node, &policy->uid_tree, policy_node) {
                bool range = false;

                r = sd_bus_message_open_container(m, 'r', "uu(" POLICY_T_BATCH ")");
                if (r < 0)
                        return error_origin(r);

                r = sd_bus_message_append(m, "uu", node->index.uidgid_start, node->index.uidgid_end);
                if (r < 0)
                        return error_origin(r);

                r = sd_bus_message_open_container(m, 'r', POLICY_T_BATCH);
                if (r < 0)
                        return error_origin(r);

                if (node->index.uidgid_start != node->index.uidgid_end)
                        range = true;

                r = policy_export_connect(policy, range ? NULL : &policy->connect_default, &node->connect_list, m);
                r = r ?: policy_export_own(policy, range ? NULL : &policy->own_default, &node->own_list, m);
                r = r ?: policy_export_xmit(policy, range ? NULL : &policy->send_default, &node->send_list, m);
                r = r ?: policy_export_xmit(policy, range ? NULL : &policy->recv_default, &node->recv_list, m);
                if (r)
                        return error_trace(r);

                r = sd_bus_message_close_container(m);
                if (r < 0)
                        return error_origin(r);

                r = sd_bus_message_close_container(m);
                if (r < 0)
                        return error_origin(r);
        }

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return error_origin(r);

        r = sd_bus_message_open_container(m, 'a', "(u(" POLICY_T_BATCH "))");
        if (r < 0)
                return error_origin(r);

        c_rbtree_for_each_entry(node, &policy->gid_tree, policy_node) {
                r = sd_bus_message_open_container(m, 'r', "u(" POLICY_T_BATCH ")");
                if (r < 0)
                        return error_origin(r);

                assert(node->index.uidgid_start == node->index.uidgid_end);

                r = sd_bus_message_append(m, "u", node->index.uidgid_start);
                if (r < 0)
                        return error_origin(r);

                r = sd_bus_message_open_container(m, 'r', POLICY_T_BATCH);
                if (r < 0)
                        return error_origin(r);

                r = policy_export_connect(policy, &policy->connect_default, &node->connect_list, m);
                r = r ?: policy_export_own(policy, NULL, &node->own_list, m);
                r = r ?: policy_export_xmit(policy, NULL, &node->send_list, m);
                r = r ?: policy_export_xmit(policy, NULL, &node->recv_list, m);
                if (r)
                        return error_trace(r);

                r = sd_bus_message_close_container(m);
                if (r < 0)
                        return error_origin(r);

                r = sd_bus_message_close_container(m);
                if (r < 0)
                        return error_origin(r);
        }

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return error_origin(r);

        r = sd_bus_message_open_container(m, 'a', "(ss)");
        if (r < 0)
                return error_origin(r);

        c_list_for_each_entry(i_record, &policy->selinux_list, link) {
                r = sd_bus_message_append(m, "(ss)",
                                          i_record->selinux.name,
                                          i_record->selinux.context);
                if (r)
                        return error_origin(r);
        }

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return error_origin(r);

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return error_origin(r);

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return error_origin(r);

        return 0;
}
