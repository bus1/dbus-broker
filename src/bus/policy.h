#pragma once

/*
 * D-Bus Policy
 */

#include <c-dvar.h>
#include <c-list.h>
#include <c-rbtree.h>
#include <c-stdaux.h>
#include <stdlib.h>
#include "dbus/protocol.h"
#include "util/ref.h"

typedef struct BusAppArmorRegistry BusAppArmorRegistry;
typedef struct BusSELinuxRegistry BusSELinuxRegistry;
typedef struct NameSet NameSet;
typedef struct PolicyBatch PolicyBatch;
typedef struct PolicyBatchName PolicyBatchName;
typedef struct PolicyRegistry PolicyRegistry;
typedef struct PolicyRegistryNode PolicyRegistryNode;
typedef struct PolicyRegistryNodeIndex PolicyRegistryNodeIndex;
typedef struct PolicySnapshot PolicySnapshot;
typedef struct PolicyVerdict PolicyVerdict;
typedef struct PolicyXmit PolicyXmit;

enum {
        _POLICY_E_SUCCESS,

        POLICY_E_INVALID,
        POLICY_E_ACCESS_DENIED,
        POLICY_E_SELINUX_ACCESS_DENIED,
        POLICY_E_APPARMOR_ACCESS_DENIED,
};

struct PolicyVerdict {
        bool verdict;
        uint64_t priority;
};

#define POLICY_VERDICT_INIT {}
#define POLICY_VERDICT_INIT_WITH(_v, _p) { .verdict = (_v), .priority = (_p) }

struct PolicyXmit {
        CList batch_link;
        PolicyVerdict verdict;
        unsigned int type;
        unsigned int broadcast;
        char *path;
        char *interface;
        char *member;
        uint64_t min_fds;
        uint64_t max_fds;
};

#define POLICY_XMIT_NULL(_x) {                                                  \
                .batch_link = C_LIST_INIT((_x).batch_link),                     \
                .verdict = POLICY_VERDICT_INIT,                                 \
                .type = DBUS_MESSAGE_TYPE_INVALID,                              \
                .max_fds = UINT64_MAX,                                          \
        }

struct PolicyBatchName {
        PolicyBatch *batch;
        CRBNode batch_node;
        PolicyVerdict own_verdict;
        PolicyVerdict own_prefix_verdict;
        CList send_unindexed;
        CList recv_unindexed;
        char name[];
};

#define POLICY_BATCH_NAME_NULL(_x) {                                            \
                .batch_node = C_RBNODE_INIT((_x).batch_node),                   \
                .own_verdict = POLICY_VERDICT_INIT,                             \
                .own_prefix_verdict = POLICY_VERDICT_INIT,                      \
                .send_unindexed = C_LIST_INIT((_x).send_unindexed),             \
                .recv_unindexed = C_LIST_INIT((_x).recv_unindexed),             \
        }

struct PolicyBatch {
        _Atomic unsigned long n_refs;
        PolicyVerdict connect_verdict;
        CRBTree name_tree;
};

#define POLICY_BATCH_NULL(_x) {                                                 \
                .n_refs = REF_INIT,                                             \
                .connect_verdict = POLICY_VERDICT_INIT,                         \
                .name_tree = C_RBTREE_INIT,                                     \
        }

struct PolicyRegistryNodeIndex {
        uint32_t uidgid_start;
        uint32_t uidgid_end;
};

#define POLICY_REGISTRY_NODE_INDEX_NULL {                                       \
                .uidgid_start = (uint32_t)-1,                                   \
                .uidgid_end = (uint32_t)-1,                                     \
        }

struct PolicyRegistryNode {
        PolicyRegistryNodeIndex index;
        CRBTree *registry_tree;
        CRBNode registry_node;
        PolicyBatch *batch;
};

#define POLICY_REGISTRY_NODE_NULL(_x) {                                         \
                .index = POLICY_REGISTRY_NODE_INDEX_NULL,                       \
                .registry_node = C_RBNODE_INIT((_x).registry_node),             \
        }

struct PolicyRegistry {
        BusAppArmorRegistry *apparmor;
        BusSELinuxRegistry *selinux;
        PolicyBatch *default_batch;
        CRBTree uid_range_tree;
        CRBTree uid_tree;
        CRBTree gid_tree;
};

#define POLICY_REGISTRY_NULL {                                                  \
                .uid_range_tree = C_RBTREE_INIT,                                \
                .uid_tree = C_RBTREE_INIT,                                      \
                .gid_tree = C_RBTREE_INIT,                                      \
        }

struct PolicySnapshot {
        BusAppArmorRegistry *apparmor;
        BusSELinuxRegistry *selinux;
        char *seclabel;
        size_t n_batches;
        PolicyBatch *batches[];
};

#define POLICY_SNAPSHOT_NULL {}

/* batches */

int policy_batch_new(PolicyBatch **batchp);
void policy_batch_free(_Atomic unsigned long *n_refs, void *userdata);

/* registry */

int policy_registry_new(PolicyRegistry **registryp, const char *fallback_seclabel);
PolicyRegistry *policy_registry_free(PolicyRegistry *registry);

int policy_registry_import(PolicyRegistry *registry, CDVar *v);

C_DEFINE_CLEANUP(PolicyRegistry *, policy_registry_free);

/* snapshots */

int policy_snapshot_new(PolicySnapshot **snapshotp,
                        PolicyRegistry *registry,
                        const char *context,
                        uint32_t uid,
                        const uint32_t *gids,
                        size_t n_gids);
PolicySnapshot *policy_snapshot_free(PolicySnapshot *snapshot);

int policy_snapshot_dup(PolicySnapshot *snapshot, PolicySnapshot **newp);

int policy_snapshot_check_connect(PolicySnapshot *snapshot);
int policy_snapshot_check_own(PolicySnapshot *snapshot, const char *name);
int policy_snapshot_check_send(PolicySnapshot *snapshot,
                               const char *subject_seclabel,
                               NameSet *subject,
                               uint64_t subject_id,
                               const char *interface,
                               const char *method,
                               const char *path,
                               unsigned int type,
                               bool broadcast,
                               size_t n_fds);
int policy_snapshot_check_receive(PolicySnapshot *snapshot,
                                  const char *subject_seclabel,
                                  NameSet *subject,
                                  uint64_t subject_id,
                                  const char *interface,
                                  const char *method,
                                  const char *path,
                                  unsigned int type,
                                  bool broadcast,
                                  size_t n_fds);

C_DEFINE_CLEANUP(PolicySnapshot *, policy_snapshot_free);

/* inline helpers */

static inline PolicyBatch *policy_batch_ref(PolicyBatch *batch) {
        if (batch)
                ref_inc(&batch->n_refs);
        return batch;
}

static inline PolicyBatch *policy_batch_unref(PolicyBatch *batch) {
        if (batch)
                ref_dec(&batch->n_refs, policy_batch_free, NULL);
        return NULL;
}

C_DEFINE_CLEANUP(PolicyBatch *, policy_batch_unref);
