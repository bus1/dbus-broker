#pragma once

/*
 * D-Bus Policy
 */

#include <c-list.h>
#include <c-rbtree.h>
#include <stdlib.h>

enum {
        _POLICY_E_SUCCESS,

        POLICY_E_ACCESS_DENIED,
};

typedef struct ConnectionPolicy ConnectionPolicy;
typedef struct ConnectionPolicyEntry ConnectionPolicyEntry;
typedef struct NameOwner NameOwner;
typedef struct OwnershipPolicy OwnershipPolicy;
typedef struct OwnershipPolicyEntry OwnershipPolicyEntry;
typedef struct Policy Policy;
typedef struct PolicyDecision PolicyDecision;
typedef struct PolicyParser PolicyParser;
typedef struct PolicyRegistry PolicyRegistry;
typedef struct PeerPolicy PeerPolicy;
typedef struct TransmissionPolicy TransmissionPolicy;
typedef struct TransmissionPolicyByName TransmissionPolicyByName;
typedef struct TransmissionPolicyEntry TransmissionPolicyEntry;

struct PolicyDecision {
        bool deny;
        uint64_t priority;
};

#define POLICY_DECISION_INIT {}

struct OwnershipPolicy {
        CRBTree names;
        CRBTree prefixes;
        PolicyDecision wildcard;
};

#define OWNERSHIP_POLICY_INIT {                         \
                .names = C_RBTREE_INIT,                 \
                .prefixes = C_RBTREE_INIT,              \
                .wildcard = POLICY_DECISION_INIT,       \
        }

struct OwnershipPolicyEntry {
        CRBTree *policy;
        PolicyDecision decision;
        CRBNode rb;
        const char name[];
};

struct ConnectionPolicy {
        CRBTree uid_tree;
        CRBTree gid_tree;
        PolicyDecision wildcard;
};

#define CONNECTION_POLICY_INIT {                        \
                .uid_tree = C_RBTREE_INIT,              \
                .gid_tree = C_RBTREE_INIT,              \
                .wildcard = POLICY_DECISION_INIT,       \
        }

struct ConnectionPolicyEntry {
        CRBTree *policy;
        PolicyDecision decision;
        CRBNode rb;
        uid_t uid;
};

struct TransmissionPolicy {
        CRBTree policy_by_name_tree;
        CList wildcard_entry_list;
};

#define TRANSMISSION_POLICY_INIT(_x) {                                          \
                .policy_by_name_tree = C_RBTREE_INIT,                           \
                .wildcard_entry_list = C_LIST_INIT((_x).wildcard_entry_list),   \
        }

struct TransmissionPolicyByName {
        CList entry_list;
        CRBTree *policy;
        CRBNode policy_node;
        const char name[];
};

struct TransmissionPolicyEntry {
        int type;
        const char *interface;
        const char *member;
        const char *path;
        PolicyDecision decision;
        CList policy_link;
};

struct Policy {
        OwnershipPolicy ownership_policy;
        TransmissionPolicy send_policy;
        TransmissionPolicy receive_policy;
        CRBTree *registry;
        CRBNode registry_node;
        uid_t uid;
};

#define POLICY_INIT(_x) {                                                               \
                .ownership_policy = OWNERSHIP_POLICY_INIT,                              \
                .send_policy = TRANSMISSION_POLICY_INIT((_x).send_policy),              \
                .receive_policy = TRANSMISSION_POLICY_INIT((_x).receive_policy),        \
                .registry_node = C_RBNODE_INIT((_x).registry_node),                     \
                .uid = -1,                                                              \
        }

struct PeerPolicy {
        Policy *uid_policy;
        Policy **gid_policies;
        size_t n_gid_policies;
};

#define PEER_POLICY_INIT {}

struct PolicyRegistry {
        ConnectionPolicy connection_policy;
        Policy wildcard_uid_policy;
        CRBTree uid_policy_tree;
        CRBTree gid_policy_tree;
};

#define POLICY_REGISTRY_INIT(_x) {                                              \
                .connection_policy = CONNECTION_POLICY_INIT,                    \
                .wildcard_uid_policy = POLICY_INIT((_x).wildcard_uid_policy),   \
                .uid_policy_tree = C_RBTREE_INIT,                               \
                .gid_policy_tree = C_RBTREE_INIT,                               \
        }

bool policy_decision_is_default(PolicyDecision *decision);

void ownership_policy_init(OwnershipPolicy *policy);
void ownership_policy_deinit(OwnershipPolicy *policy);

bool ownership_policy_is_empty(OwnershipPolicy *policy);

int ownership_policy_set_wildcard(OwnershipPolicy *policy, bool deny, uint64_t priority);
int ownership_policy_add_prefix(OwnershipPolicy *policy, const char *prefix, bool deny, uint64_t priority);
int ownership_policy_add_name(OwnershipPolicy *policy, const char *name, bool deny, uint64_t priority);

void connection_policy_init(ConnectionPolicy *policy);
void connection_policy_deinit(ConnectionPolicy *policy);

bool connection_policy_is_empty(ConnectionPolicy *policy);

int connection_policy_set_wildcard(ConnectionPolicy *policy, bool deny, uint64_t priority);
int connection_policy_add_uid(ConnectionPolicy *policy, uid_t uid, bool deny, uint64_t priority);
int connection_policy_add_gid(ConnectionPolicy *policy, gid_t gid, bool deny, uint64_t priority);

int connection_policy_instantiate(ConnectionPolicy *target, ConnectionPolicy *source);

void transmission_policy_init(TransmissionPolicy *policy);
void transmission_policy_deinit(TransmissionPolicy *policy);

bool transmission_policy_is_empty(TransmissionPolicy *policy);

int transmission_policy_add_entry(TransmissionPolicy *policy,
                                  const char *name, const char *interface, const char *method, const char *path, int type,
                                  bool deny, uint64_t priority);

void policy_init(Policy *policy);
void policy_deinit(Policy *policy);

bool policy_is_empty(Policy *policy);
int policy_instantiate(Policy *target, Policy *source);

int peer_policy_instantiate(PeerPolicy *policy, PolicyRegistry *registry, uid_t uid, gid_t *gids, size_t n_gids);
void peer_policy_deinit(PeerPolicy *policy);

int peer_policy_check_own(PeerPolicy *policy, const char *name);
int peer_policy_check_send(PeerPolicy *policy, NameOwner *subject, const char *interface, const char *method, const char *path, int type);
int peer_policy_check_receive(PeerPolicy *policy, NameOwner *subject, const char *interface, const char *method, const char *path, int type);

void policy_registry_init(PolicyRegistry *registry);
void policy_registry_deinit(PolicyRegistry *registry);

bool policy_registry_needs_groups(PolicyRegistry *registry);

int policy_registry_get_policy_by_uid(PolicyRegistry *registry, Policy **policyp, uid_t uid);
int policy_registry_get_policy_by_gid(PolicyRegistry *registry, Policy **policyp, gid_t gid);
