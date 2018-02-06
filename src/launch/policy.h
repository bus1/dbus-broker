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
typedef struct PolicyEntries PolicyEntries;
typedef struct PolicyNode PolicyNode;
typedef struct PolicyNodeIndex PolicyNodeIndex;
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
                } xmit;

                struct {
                        const char *name;
                        const char *context;
                } selinux;
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

#define POLICY_RECORD_INIT_SELINUX(_x) {                                        \
                .link = C_LIST_INIT((_x).link),                                 \
        }

struct PolicyEntries {
        CList connect_list;
        CList own_list;
        CList send_list;
        CList recv_list;
};

#define POLICY_ENTRIES_NULL(_x) {                                               \
                .connect_list = C_LIST_INIT((_x).connect_list),                 \
                .own_list = C_LIST_INIT((_x).own_list),                         \
                .send_list = C_LIST_INIT((_x).send_list),                       \
                .recv_list = C_LIST_INIT((_x).recv_list),                       \
        }

struct PolicyNodeIndex {
        uint32_t uidgid_start;
        uint32_t uidgid_end;
};

#define POLICY_NODE_INDEX_NULL {                                                \
                .uidgid_start = (uint32_t)-1,                                   \
                .uidgid_end = (uint32_t)-1,                                     \
        }                                                                       \

struct PolicyNode {
        PolicyNodeIndex index;
        CRBNode policy_node;

        PolicyEntries entries;
};

#define POLICY_NODE_NULL(_x) {                                                  \
                .index = POLICY_NODE_INDEX_NULL,                                \
                .policy_node = C_RBNODE_INIT((_x).policy_node),                 \
                .entries = POLICY_ENTRIES_NULL((_x).entries),                   \
        }

struct Policy {
        uint64_t i_priority;

        PolicyEntries default_entries;

        CRBTree uid_tree;
        CRBTree gid_tree;

        CList selinux_list;
};

#define POLICY_INIT(_x) {                                                       \
                .default_entries = POLICY_ENTRIES_NULL((_x).default_entries),   \
                .uid_tree = C_RBTREE_INIT,                                      \
                .gid_tree = C_RBTREE_INIT,                                      \
                .selinux_list = C_LIST_INIT((_x).selinux_list)                  \
        }

/* records */

int policy_record_new_connect(PolicyRecord **recordp);
int policy_record_new_own(PolicyRecord **recordp);
int policy_record_new_xmit(PolicyRecord **recordp);
int policy_record_new_selinux(PolicyRecord **recordp);
PolicyRecord *policy_record_free(PolicyRecord *record);

C_DEFINE_CLEANUP(PolicyRecord *, policy_record_free);

/* policy */

void policy_init(Policy *policy);
void policy_deinit(Policy *policy);

int policy_import(Policy *policy, ConfigRoot *root);
void policy_optimize(Policy *policy);
int policy_export(Policy *policy, sd_bus_message *m);

C_DEFINE_CLEANUP(Policy *, policy_deinit);
