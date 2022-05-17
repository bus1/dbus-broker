#pragma once

/*
 * D-Bus Policy Converter
 */

#include <c-list.h>
#include <c-rbtree.h>
#include <c-stdaux.h>
#include <stdlib.h>
#include <systemd/sd-bus.h>
#include "launch/config.h"

typedef struct Policy Policy;
typedef struct PolicyEntries PolicyEntries;
typedef struct PolicyNode PolicyNode;
typedef struct PolicyRecord PolicyRecord;

#define POLICY_PRIORITY_DEFAULT (UINT64_C(1))

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
                        unsigned int broadcast;
                        uint64_t min_fds;
                        uint64_t max_fds;
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

struct PolicyNode {
        uint32_t uidgid;
        CRBNode policy_node;

        PolicyEntries entries;
};

#define POLICY_NODE_NULL(_x) {                                                  \
                .uidgid = -1,                                                   \
                .policy_node = C_RBNODE_INIT((_x).policy_node),                 \
                .entries = POLICY_ENTRIES_NULL((_x).entries),                   \
        }

struct Policy {
        uint64_t i_priority;

        PolicyEntries default_entries;
        PolicyEntries at_console_entries;
        PolicyEntries no_console_entries;

        CRBTree uid_tree;
        CRBTree gid_tree;

        CList selinux_list;
        unsigned int apparmor_mode;
        char *bus_type;
};

#define POLICY_INIT(_x) {                                                               \
                .i_priority = POLICY_PRIORITY_DEFAULT,                                  \
                .default_entries = POLICY_ENTRIES_NULL((_x).default_entries),           \
                .at_console_entries = POLICY_ENTRIES_NULL((_x).at_console_entries),     \
                .no_console_entries = POLICY_ENTRIES_NULL((_x).no_console_entries),     \
                .uid_tree = C_RBTREE_INIT,                                              \
                .gid_tree = C_RBTREE_INIT,                                              \
                .selinux_list = C_LIST_INIT((_x).selinux_list),                         \
                .apparmor_mode = CONFIG_APPARMOR_ENABLED,                               \
                .bus_type = NULL,                                                       \
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
int policy_export(Policy *policy, sd_bus_message *m, uint32_t *at_console_uids, size_t n_at_console_uids);

C_DEFINE_CLEANUP(Policy *, policy_deinit);
