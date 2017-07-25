/*
 * D-Bus Policy Converter
 */

#include <c-list.h>
#include <c-macro.h>
#include <stdlib.h>
#include <systemd/sd-bus.h>
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
 * policy_record_free() - XXX
 */
PolicyRecord *policy_record_free(PolicyRecord *record) {
        if (!record)
                return NULL;

        c_list_unlink_init(&record->link);
        free(record);

        return NULL;
}

static int policy_map_node_new(PolicyMapNode **nodep) {
        PolicyMapNode *node;

        node = calloc(1, sizeof(*node));
        if (!node)
                return error_origin(-ENOMEM);

        *node = (PolicyMapNode)POLICY_MAP_NODE_INIT(*node);

        *nodep = node;
        node = NULL;
        return 0;
}

static PolicyMapNode *policy_map_node_free(PolicyMapNode *node) {
        PolicyRecord *record;

        if (!node)
                return NULL;

        while ((record = c_list_first_entry(&node->record_list, PolicyRecord, link)))
                policy_record_free(record);

        c_list_unlink_init(&node->map_link);
        free(node);

        return NULL;
}

/**
 * policy_map_init() - XXX
 */
void policy_map_init(PolicyMap *map) {
        *map = (PolicyMap)POLICY_MAP_INIT(*map);
}

/**
 * policy_map_deinit() - XXX
 */
void policy_map_deinit(PolicyMap *map) {
        PolicyMapNode *node;

        while ((node = c_list_first_entry(&map->node_list, PolicyMapNode, map_link)))
                policy_map_node_free(node);
}

/**
 * policy_map_at() - XXX
 */
int policy_map_at(PolicyMap *map, PolicyMapNode **nodep, uint32_t uidgid) {
        PolicyMapNode *node;
        int r;

        c_list_for_each_entry(node, &map->node_list, map_link) {
                if (uidgid == node->uidgid) {
                        *nodep = node;
                        return 0;
                }
        }

        r = policy_map_node_new(&node);
        if (r)
                return error_trace(r);

        node->uidgid = uidgid;
        c_list_link_tail(&map->node_list, &node->map_link);

        *nodep = node;
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

static int policy_import_link(Policy *policy,
                              PolicyRecord *record,
                              PolicyMap *map,
                              CList *list,
                              uint32_t id) {
        PolicyMapNode *node;
        int r;

        if (id != (uint32_t)-1) {
                r = policy_map_at(map, &node, id);
                if (r)
                        return r;

                list = &node->record_list;
        }

        c_list_link_tail(list, &record->link);

        return 0;
}

static int policy_import_connect(Policy *policy, ConfigNode *cnode) {
        _c_cleanup_(policy_record_freep) PolicyRecord *record = NULL;
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

        r = policy_import_link(
                        policy,
                        record,
                        cnode->allow_deny.user ?
                                &policy->connect_uid :
                                &policy->connect_gid,
                        &policy->connect_default,
                        cnode->allow_deny.user ?
                                cnode->allow_deny.uid :
                                cnode->allow_deny.group ?
                                        cnode->allow_deny.gid :
                                        (uint32_t)-1);
        if (r)
                return error_trace(r);

        record = NULL;
        return 0;
}

static int policy_import_own(Policy *policy, ConfigNode *cnode) {
        _c_cleanup_(policy_record_freep) PolicyRecord *record = NULL;
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

        r = policy_import_link(
                        policy,
                        record,
                        cnode->parent->policy.context == CONFIG_POLICY_USER ?
                                &policy->own_uid :
                                &policy->own_gid,
                        &policy->own_default,
                        (cnode->parent->policy.context == CONFIG_POLICY_USER ||
                         cnode->parent->policy.context == CONFIG_POLICY_GROUP) ?
                                cnode->parent->policy.id : (uint32_t)-1);
        if (r)
                return error_trace(r);

        record = NULL;
        return 0;
}

static int policy_import_send(Policy *policy, ConfigNode *cnode) {
        _c_cleanup_(policy_record_freep) PolicyRecord *record = NULL;
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

        if (cnode->allow_deny.send_error ||
            cnode->allow_deny.send_requested_reply) {
                fprintf(stderr, "Reply/Error policy in %s +%lu: Explicit policies on replies and errors are deprecated and ignored\n",
                        cnode->file, cnode->lineno);
                return 0;
        }

        r = policy_record_new_xmit(&record);
        if (r)
                return error_trace(r);

        policy_import_verdict(policy, record, cnode);

        record->xmit.name = cnode->allow_deny.send_destination;
        record->xmit.path = cnode->allow_deny.send_path;
        record->xmit.interface = cnode->allow_deny.send_interface;
        record->xmit.member = cnode->allow_deny.send_member;
        record->xmit.type = cnode->allow_deny.send_type;
        record->xmit.eavesdrop = cnode->allow_deny.eavesdrop;

        r = policy_import_link(
                        policy,
                        record,
                        cnode->parent->policy.context == CONFIG_POLICY_USER ?
                                &policy->send_uid :
                                &policy->send_gid,
                        &policy->send_default,
                        (cnode->parent->policy.context == CONFIG_POLICY_USER ||
                         cnode->parent->policy.context == CONFIG_POLICY_GROUP) ?
                                cnode->parent->policy.id : (uint32_t)-1);
        if (r)
                return error_trace(r);

        record = NULL;
        return 0;
}

static int policy_import_recv(Policy *policy, ConfigNode *cnode) {
        _c_cleanup_(policy_record_freep) PolicyRecord *record = NULL;
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

        if (cnode->allow_deny.recv_error ||
            cnode->allow_deny.recv_requested_reply) {
                fprintf(stderr, "Reply/Error policy in %s +%lu: Explicit policies on replies and errors are deprecated and ignored\n",
                        cnode->file, cnode->lineno);
                return 0;
        }

        r = policy_record_new_xmit(&record);
        if (r)
                return error_trace(r);

        policy_import_verdict(policy, record, cnode);

        record->xmit.name = cnode->allow_deny.recv_sender;
        record->xmit.path = cnode->allow_deny.recv_path;
        record->xmit.interface = cnode->allow_deny.recv_interface;
        record->xmit.member = cnode->allow_deny.recv_member;
        record->xmit.type = cnode->allow_deny.recv_type;
        record->xmit.eavesdrop = cnode->allow_deny.eavesdrop;

        r = policy_import_link(
                        policy,
                        record,
                        cnode->parent->policy.context == CONFIG_POLICY_USER ?
                                &policy->recv_uid :
                                &policy->recv_gid,
                        &policy->recv_default,
                        (cnode->parent->policy.context == CONFIG_POLICY_USER ||
                         cnode->parent->policy.context == CONFIG_POLICY_GROUP) ?
                                cnode->parent->policy.id : (uint32_t)-1);
        if (r)
                return error_trace(r);

        record = NULL;
        return 0;
}

/**
 * policy_import() - XXX
 */
int policy_import(Policy *policy, ConfigRoot *root) {
        ConfigNode *i_cnode;
        int r;

        c_list_for_each_entry(i_cnode, &root->node_list, root_link) {
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

                if (i_cnode->parent->policy.context == CONFIG_POLICY_AT_CONSOLE) {
                        fprintf(stderr, "Policy record in console-context in %s +%lu: at_console=true is deprecated and ignored\n",
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
                           i_cnode->allow_deny.recv_requested_reply) {
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
        PolicyMapNode *i_node, *t_node;
        PolicyRecord *top_default, *top;

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
        c_list_for_each_entry_safe(i_node, t_node, &policy->connect_uid.node_list, map_link) {
                top = policy_list_find_top(&i_node->record_list);
                if (top_default && (!top || top_default->priority >= top->priority))
                        policy_map_node_free(i_node);
                else
                        policy_list_shrink(&i_node->record_list, top);
        }

        /* shrink each gid-map down to 1 entry (or 0 if below @top_default) */
        c_list_for_each_entry_safe(i_node, t_node, &policy->connect_gid.node_list, map_link) {
                top = policy_list_find_top(&i_node->record_list);
                if (top_default && (!top || top_default->priority >= top->priority))
                        policy_map_node_free(i_node);
                else
                        policy_list_shrink(&i_node->record_list, top);
        }
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
}

static int policy_export_connect_default(Policy *policy, sd_bus_message *m) {
        PolicyRecord *top;
        int r;

        top = c_list_first_entry(&policy->connect_default, PolicyRecord, link);
        /* list must be empty or singular */
        assert(top == c_list_last_entry(&policy->connect_default, PolicyRecord, link));

        r = sd_bus_message_append(m, "b", top ? top->verdict : false);
        if (r < 0)
                return error_origin(r);

        return 0;
}

static int policy_export_connect_uidgid(PolicyMap *map, sd_bus_message *m) {
        PolicyMapNode *i_node;
        PolicyRecord *top;
        int r;

        r = sd_bus_message_open_container(m, 'a', "(ub)");
        if (r < 0)
                return error_origin(r);

        c_list_for_each_entry(i_node, &map->node_list, map_link) {
                top = c_list_first_entry(&i_node->record_list, PolicyRecord, link);
                /* list must be empty or singular */
                assert(top == c_list_last_entry(&i_node->record_list, PolicyRecord, link));

                if (top) {
                        r = sd_bus_message_append(m, "(ub)", i_node->uidgid, top->verdict);
                        if (r < 0)
                                return error_origin(r);
                }
        }

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return error_origin(r);

        return 0;
}

static int policy_export_own_default(Policy *policy, sd_bus_message *m) {
        PolicyRecord *i_record;
        int r;

        r = sd_bus_message_open_container(m, 'a', "(btbs)");
        if (r < 0)
                return error_origin(r);

        c_list_for_each_entry(i_record, &policy->own_default, link) {
                r = sd_bus_message_append(m,
                                          "(btbs)",
                                          i_record->verdict,
                                          i_record->priority,
                                          i_record->own.prefix,
                                          i_record->own.name);
                if (r < 0)
                        return error_origin(r);
        }

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return error_origin(r);

        return 0;
}

static int policy_export_own_uidgid(PolicyMap *map, sd_bus_message *m) {
        PolicyRecord *i_record;
        PolicyMapNode *i_node;
        int r;

        r = sd_bus_message_open_container(m, 'a', "(ua(btbs))");
        if (r < 0)
                return error_origin(r);

        c_list_for_each_entry(i_node, &map->node_list, map_link) {
                r = sd_bus_message_open_container(m, 'r', "ua(btbs)");
                if (r < 0)
                        return error_origin(r);

                r = sd_bus_message_append(m, "u", i_node->uidgid);
                if (r < 0)
                        return error_origin(r);

                r = sd_bus_message_open_container(m, 'a', "(btbs)");
                if (r < 0)
                        return error_origin(r);

                c_list_for_each_entry(i_record, &i_node->record_list, link) {
                        r = sd_bus_message_append(m,
                                                  "(btbs)",
                                                  i_record->verdict,
                                                  i_record->priority,
                                                  i_record->own.prefix,
                                                  i_record->own.name);
                        if (r < 0)
                                return error_origin(r);
                }

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

        return 0;
}

static int policy_export_xmit_default(CList *list, sd_bus_message *m) {
        PolicyRecord *i_record;
        int r;

        r = sd_bus_message_open_container(m, 'a', "(btsssssb)");
        if (r < 0)
                return error_origin(r);

        c_list_for_each_entry(i_record, list, link) {
                r = sd_bus_message_append(m,
                                          "(btsssssb)",
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

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return error_origin(r);

        return 0;
}

static int policy_export_xmit_uidgid(PolicyMap *map, sd_bus_message *m) {
        PolicyRecord *i_record;
        PolicyMapNode *i_node;
        int r;

        r = sd_bus_message_open_container(m, 'a', "(ua(btsssssb))");
        if (r < 0)
                return error_origin(r);

        c_list_for_each_entry(i_node, &map->node_list, map_link) {
                r = sd_bus_message_open_container(m, 'r', "ua(btsssssb)");
                if (r < 0)
                        return error_origin(r);

                r = sd_bus_message_append(m, "u", i_node->uidgid);
                if (r < 0)
                        return error_origin(r);

                r = sd_bus_message_open_container(m, 'a', "(btsssssb)");
                if (r < 0)
                        return error_origin(r);

                c_list_for_each_entry(i_record, &i_node->record_list, link) {
                        r = sd_bus_message_append(m,
                                                  "(btsssssb)",
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

        return 0;
}

#define POLICY_T "("                                                            \
                        "b"                                                     \
                        "a(ub)"                                                 \
                        "a(ub)"                                                 \
                ")("                                                            \
                        "a(btbs)"                                               \
                        "a(ua(btbs))"                                           \
                        "a(ua(btbs))"                                           \
                ")("                                                            \
                        "a(btsssssb)"                                           \
                        "a(ua(btsssssb))"                                       \
                        "a(ua(btsssssb))"                                       \
                ")("                                                            \
                        "a(btsssssb)"                                           \
                        "a(ua(btsssssb))"                                       \
                        "a(ua(btsssssb))"                                       \
                ")"

/**
 * policy_export() - XXX
 */
int policy_export(Policy *policy, sd_bus_message *m) {
        int r;

        r = sd_bus_message_open_container(m, 'v', "(" POLICY_T ")");
        if (r < 0)
                return error_origin(r);

        r = sd_bus_message_open_container(m, 'r', POLICY_T);
        if (r < 0)
                return error_origin(r);

        r = sd_bus_message_open_container(m, 'r',
                                                "b"
                                                "a(ub)"
                                                "a(ub)");
        if (r < 0)
                return error_origin(r);

        r = policy_export_connect_default(policy, m);
        r = r ?: policy_export_connect_uidgid(&policy->connect_uid, m);
        r = r ?: policy_export_connect_uidgid(&policy->connect_gid, m);
        if (r)
                return error_trace(r);

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return error_origin(r);

        r = sd_bus_message_open_container(m, 'r',
                                                "a(btbs)"
                                                "a(ua(btbs))"
                                                "a(ua(btbs))");
        if (r < 0)
                return error_origin(r);

        r = policy_export_own_default(policy, m);
        r = r ?: policy_export_own_uidgid(&policy->own_uid, m);
        r = r ?: policy_export_own_uidgid(&policy->own_gid, m);
        if (r)
                return error_trace(r);

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return error_origin(r);

        r = sd_bus_message_open_container(m, 'r',
                                                "a(btsssssb)"
                                                "a(ua(btsssssb))"
                                                "a(ua(btsssssb))");
        if (r < 0)
                return error_origin(r);

        r = policy_export_xmit_default(&policy->send_default, m);
        r = r ?: policy_export_xmit_uidgid(&policy->send_uid, m);
        r = r ?: policy_export_xmit_uidgid(&policy->send_gid, m);
        if (r)
                return error_trace(r);

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return error_origin(r);

        r = sd_bus_message_open_container(m, 'r',
                                                "a(btsssssb)"
                                                "a(ua(btsssssb))"
                                                "a(ua(btsssssb))");
        if (r < 0)
                return error_origin(r);

        r = policy_export_xmit_default(&policy->recv_default, m);
        r = r ?: policy_export_xmit_uidgid(&policy->recv_uid, m);
        r = r ?: policy_export_xmit_uidgid(&policy->recv_gid, m);
        if (r)
                return error_trace(r);

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
