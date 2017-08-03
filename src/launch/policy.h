#pragma once

/*
 * D-Bus Policy Converter
 */

#include <c-list.h>
#include <c-macro.h>
#include <c-rbtree.h>
#include <stdlib.h>
#include <systemd/sd-bus.h>
#include "launch/config.h"

typedef struct Policy Policy;
typedef struct PolicyNode PolicyNode;
typedef struct PolicyRecord PolicyRecord;

struct PolicyRecord {
        CList link;

        bool verdict;
        uint64_t priority;

        union {
                struct {
                        bool prefix;
                        const char *name;
                } own;

                struct {
                        const char *name;
                        const char *path;
                        const char *interface;
                        const char *member;
                        unsigned int type;
                        bool eavesdrop;
                } xmit;
        };
};

#define POLICY_RECORD_INIT_CONNECT(_x) {                                        \
                .link = C_LIST_INIT((_x).link),                                 \
        }

#define POLICY_RECORD_INIT_OWN(_x) {                                            \
                .link = C_LIST_INIT((_x).link),                                 \
        }

#define POLICY_RECORD_INIT_XMIT(_x) {                                           \
                .link = C_LIST_INIT((_x).link),                                 \
        }

struct PolicyNode {
        uint32_t uidgid;
        CRBTree *policy_tree;
        CRBNode policy_node;

        CList connect_list;
        CList own_list;
        CList send_list;
        CList recv_list;
};

#define POLICY_NODE_NULL(_x) {                                                  \
                .uidgid = (uint32_t)-1,                                         \
                .policy_node = C_RBNODE_INIT((_x).policy_node),                 \
                .connect_list = C_LIST_INIT((_x).connect_list),                 \
                .own_list = C_LIST_INIT((_x).own_list),                         \
                .send_list = C_LIST_INIT((_x).send_list),                       \
                .recv_list = C_LIST_INIT((_x).recv_list),                       \
        }

struct Policy {
        uint64_t i_priority;

        CList connect_default;
        CList own_default;
        CList send_default;
        CList recv_default;

        CRBTree uid_tree;
        CRBTree gid_tree;
};

#define POLICY_INIT(_x) {                                                       \
                .connect_default = C_LIST_INIT((_x).connect_default),           \
                .own_default = C_LIST_INIT((_x).own_default),                   \
                .send_default = C_LIST_INIT((_x).send_default),                 \
                .recv_default = C_LIST_INIT((_x).recv_default),                 \
                .uid_tree = C_RBTREE_INIT,                                      \
                .gid_tree = C_RBTREE_INIT,                                      \
        }

/* records */

int policy_record_new_connect(PolicyRecord **recordp);
int policy_record_new_own(PolicyRecord **recordp);
int policy_record_new_xmit(PolicyRecord **recordp);
PolicyRecord *policy_record_free(PolicyRecord *record);

C_DEFINE_CLEANUP(PolicyRecord *, policy_record_free);

/* policy */

void policy_init(Policy *policy);
void policy_deinit(Policy *policy);

int policy_import(Policy *policy, ConfigRoot *root);
void policy_optimize(Policy *policy);
int policy_export(Policy *policy, sd_bus_message *m);

C_DEFINE_CLEANUP(Policy *, policy_deinit);
