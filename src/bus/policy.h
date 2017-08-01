#pragma once

/*
 * D-Bus Policy
 */

#include <c-list.h>
#include <c-macro.h>
#include <c-rbtree.h>
#include <c-ref.h>
#include <stdlib.h>

enum {
        _POLICY_E_SUCCESS,

        POLICY_E_ACCESS_DENIED,
};

typedef struct NameSet NameSet;
typedef struct Policy Policy;
typedef struct PolicyConnect PolicyConnect;
typedef struct PolicyConnectEntry PolicyConnectEntry;
typedef struct PolicyDecision PolicyDecision;
typedef struct PolicyOwn PolicyOwn;
typedef struct PolicyOwnEntry PolicyOwnEntry;
typedef struct PolicyParser PolicyParser;
typedef struct PolicyRegistry PolicyRegistry;
typedef struct PolicyXmit PolicyXmit;
typedef struct PolicyXmitByName PolicyXmitByName;
typedef struct PolicyXmitEntry PolicyXmitEntry;
typedef struct PeerPolicy PeerPolicy;

struct PolicyDecision {
        bool deny;
        uint64_t priority;
};

#define POLICY_DECISION_INIT {}

struct PolicyOwn {
        CRBTree names;
        CRBTree prefixes;
        PolicyDecision wildcard;
};

#define POLICY_OWN_INIT {                               \
                .names = C_RBTREE_INIT,                 \
                .prefixes = C_RBTREE_INIT,              \
                .wildcard = POLICY_DECISION_INIT,       \
        }

struct PolicyOwnEntry {
        CRBTree *policy;
        PolicyDecision decision;
        CRBNode rb;
        const char name[];
};

struct PolicyConnect {
        CRBTree uid_tree;
        CRBTree gid_tree;
        PolicyDecision wildcard;
};

#define POLICY_CONNECT_INIT {                           \
                .uid_tree = C_RBTREE_INIT,              \
                .gid_tree = C_RBTREE_INIT,              \
                .wildcard = POLICY_DECISION_INIT,       \
        }

struct PolicyConnectEntry {
        CRBTree *policy;
        PolicyDecision decision;
        CRBNode rb;
        uid_t uid;
};

struct PolicyXmit {
        CRBTree policy_by_name_tree;
        CList wildcard_entry_list;
};

#define POLICY_XMIT_INIT(_x) {                                                  \
                .policy_by_name_tree = C_RBTREE_INIT,                           \
                .wildcard_entry_list = C_LIST_INIT((_x).wildcard_entry_list),   \
        }

struct PolicyXmitByName {
        CList entry_list;
        CRBTree *policy;
        CRBNode policy_node;
        const char name[];
};

struct PolicyXmitEntry {
        int type;
        const char *interface;
        const char *member;
        const char *path;
        PolicyDecision decision;
        CList policy_link;
};

struct Policy {
        _Atomic unsigned long n_refs;
        PolicyOwn policy_own;
        PolicyXmit policy_send;
        PolicyXmit policy_receive;
        CRBNode registry_node;
        uid_t uid;
};

#define POLICY_INIT(_x) {                                                       \
                .n_refs = C_REF_INIT,                                           \
                .policy_own = POLICY_OWN_INIT,                                  \
                .policy_send = POLICY_XMIT_INIT((_x).policy_send),              \
                .policy_receive = POLICY_XMIT_INIT((_x).policy_receive),        \
                .registry_node = C_RBNODE_INIT((_x).registry_node),             \
                .uid = -1,                                                      \
        }

struct PeerPolicy {
        Policy *uid_policy;
        Policy **gid_policies;
        size_t n_gid_policies;
};

#define PEER_POLICY_INIT {}

struct PolicyRegistry {
        PolicyConnect policy_connect;
        Policy *wildcard_uid_policy;
        CRBTree uid_policy_tree;
        CRBTree gid_policy_tree;
};

#define POLICY_REGISTRY_NULL(_x) {                                              \
                .policy_connect = POLICY_CONNECT_INIT,                    \
                .uid_policy_tree = C_RBTREE_INIT,                               \
                .gid_policy_tree = C_RBTREE_INIT,                               \
        }

bool policy_decision_is_default(PolicyDecision *decision);

void policy_own_init(PolicyOwn *policy);
void policy_own_deinit(PolicyOwn *policy);

bool policy_own_is_empty(PolicyOwn *policy);

int policy_own_set_wildcard(PolicyOwn *policy, bool deny, uint64_t priority);
int policy_own_add_prefix(PolicyOwn *policy, const char *prefix, bool deny, uint64_t priority);
int policy_own_add_name(PolicyOwn *policy, const char *name, bool deny, uint64_t priority);

void policy_connect_init(PolicyConnect *policy);
void policy_connect_deinit(PolicyConnect *policy);

bool policy_connect_is_empty(PolicyConnect *policy);

int policy_connect_set_wildcard(PolicyConnect *policy, bool deny, uint64_t priority);
int policy_connect_add_uid(PolicyConnect *policy, uid_t uid, bool deny, uint64_t priority);
int policy_connect_add_gid(PolicyConnect *policy, gid_t gid, bool deny, uint64_t priority);

int policy_connect_instantiate(PolicyConnect *target, PolicyConnect *source);

void policy_xmit_init(PolicyXmit *policy);
void policy_xmit_deinit(PolicyXmit *policy);

bool policy_xmit_is_empty(PolicyXmit *policy);

int policy_xmit_add_entry(PolicyXmit *policy,
                          const char *name, const char *interface, const char *method, const char *path, int type,
                          bool deny, uint64_t priority);

void policy_init(Policy *policy);
void policy_deinit(Policy *policy);

bool policy_is_empty(Policy *policy);
int policy_instantiate(Policy *target, Policy *source);

void policy_free(_Atomic unsigned long *n_refs, void *userdata);

int peer_policy_instantiate(PeerPolicy *policy, PolicyRegistry *registry, uid_t uid, gid_t *gids, size_t n_gids);
int peer_policy_copy(PeerPolicy *target, PeerPolicy *source);
void peer_policy_deinit(PeerPolicy *policy);

int peer_policy_check_own(PeerPolicy *policy, const char *name);
int peer_policy_check_send(PeerPolicy *policy, NameSet *subject, const char *interface, const char *method, const char *path, int type);
int peer_policy_check_receive(PeerPolicy *policy, NameSet *subject, const char *interface, const char *method, const char *path, int type);

int policy_registry_init(PolicyRegistry *registry);
void policy_registry_deinit(PolicyRegistry *registry);

bool policy_registry_needs_groups(PolicyRegistry *registry);

int policy_registry_get_policy_by_uid(PolicyRegistry *registry, Policy **policyp, uid_t uid);
int policy_registry_get_policy_by_gid(PolicyRegistry *registry, Policy **policyp, gid_t gid);

/* inline helpers */

static inline Policy *policy_ref(Policy *policy) {
        if (policy)
                c_ref_inc(&policy->n_refs);
        return policy;
}

static inline Policy *policy_unref(Policy *policy) {
        if (policy)
                c_ref_dec(&policy->n_refs, policy_free, NULL);
        return NULL;
}
