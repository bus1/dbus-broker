#pragma once

/*
 * D-Bus Policy Converter
 */

#include <c-list.h>
#include <c-macro.h>
#include <stdlib.h>
#include <systemd/sd-bus.h>
#include "launch/config.h"

typedef struct Policy Policy;
typedef struct PolicyMap PolicyMap;
typedef struct PolicyMapNode PolicyMapNode;
typedef struct PolicyRecord PolicyRecord;
typedef struct PolicyRecordOwn PolicyRecordOwn;
typedef struct PolicyRecordXmit PolicyRecordXmit;

struct PolicyRecord {
        CList link;

        bool verdict;
        uint64_t priority;

        union {
                struct PolicyRecordOwn {
                        bool prefix;
                        const char *name;
                } own;

                struct PolicyRecordXmit {
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

struct PolicyMapNode {
        uint32_t uidgid;
        CList map_link;
        CList record_list;
};

#define POLICY_MAP_NODE_INIT(_x) {                                              \
                .uidgid = (uint32_t)-1,                                         \
                .map_link = C_LIST_INIT((_x).map_link),                         \
                .record_list = C_LIST_INIT((_x).record_list),                   \
        }

struct PolicyMap {
        CList node_list;
};

#define POLICY_MAP_INIT(_x) {                                                   \
                .node_list = C_LIST_INIT((_x).node_list),                       \
        }

struct Policy {
        uint64_t i_priority;

        CList connect_default;
        PolicyMap connect_uid;
        PolicyMap connect_gid;

        CList own_default;
        PolicyMap own_uid;
        PolicyMap own_gid;

        CList send_default;
        PolicyMap send_uid;
        PolicyMap send_gid;

        CList recv_default;
        PolicyMap recv_uid;
        PolicyMap recv_gid;
};

#define POLICY_INIT(_x) {                                                       \
                .connect_default = C_LIST_INIT((_x).connect_default),           \
                .connect_uid = POLICY_MAP_INIT((_x).connect_uid),               \
                .connect_gid = POLICY_MAP_INIT((_x).connect_gid),               \
                .own_default = C_LIST_INIT((_x).own_default),                   \
                .own_uid = POLICY_MAP_INIT((_x).own_uid),                       \
                .own_gid = POLICY_MAP_INIT((_x).own_gid),                       \
                .send_default = C_LIST_INIT((_x).send_default),                 \
                .send_uid = POLICY_MAP_INIT((_x).send_uid),                     \
                .send_gid = POLICY_MAP_INIT((_x).send_gid),                     \
                .recv_default = C_LIST_INIT((_x).recv_default),                 \
                .recv_uid = POLICY_MAP_INIT((_x).recv_uid),                     \
                .recv_gid = POLICY_MAP_INIT((_x).recv_gid),                     \
        }

/* records */

int policy_record_new_connect(PolicyRecord **recordp);
int policy_record_new_own(PolicyRecord **recordp);
int policy_record_new_xmit(PolicyRecord **recordp);
PolicyRecord *policy_record_free(PolicyRecord *record);

C_DEFINE_CLEANUP(PolicyRecord *, policy_record_free);

/* maps */

void policy_map_init(PolicyMap *map);
void policy_map_deinit(PolicyMap *map);

int policy_map_at(PolicyMap *map, PolicyMapNode **nodep, uint32_t uidgid);

C_DEFINE_CLEANUP(PolicyMap *, policy_map_deinit);

/* policy */

void policy_init(Policy *policy);
void policy_deinit(Policy *policy);

int policy_import(Policy *policy, ConfigRoot *root);
void policy_optimize(Policy *policy);
int policy_export(Policy *policy, sd_bus_message *m);

C_DEFINE_CLEANUP(Policy *, policy_deinit);
