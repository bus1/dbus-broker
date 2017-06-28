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
        POLICY_E_INVALID_XML,
        POLICY_E_CIRCULAR_INCLUDE,
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
typedef struct TransmissionPolicy TransmissionPolicy;
typedef struct TransmissionPolicyByName TransmissionPolicyByName;
typedef struct TransmissionPolicyEntry TransmissionPolicyEntry;

struct PolicyDecision {
        bool deny;
        uint64_t priority;
};

struct OwnershipPolicy {
        CRBTree names;
        CRBTree prefixes;
        PolicyDecision wildcard;
};

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
                .send_policy = TRANSMISSION_POLICY_INIT((_x).send_policy),              \
                .receive_policy = TRANSMISSION_POLICY_INIT((_x).receive_policy),        \
                .registry_node = C_RBNODE_INIT((_x).registry_node),                     \
                .uid = -1,                                                              \
        }

struct PolicyRegistry {
        ConnectionPolicy connection_policy;
        Policy default_policy;
        CRBTree uid_policy_tree;
        CRBTree gid_policy_tree;
        Policy at_console_policy;
        Policy not_at_console_policy;
};

#define POLICY_REGISTRY_INIT(_x) {                                                      \
                .default_policy = POLICY_INIT((_x).default_policy),                     \
                .at_console_policy = POLICY_INIT((_x).at_console_policy),               \
                .not_at_console_policy = POLICY_INIT((_x).not_at_console_policy),       \
        }

bool policy_decision_is_default(PolicyDecision *decision);

void ownership_policy_init(OwnershipPolicy *policy);
void ownership_policy_deinit(OwnershipPolicy *policy);

bool ownership_policy_is_empty(OwnershipPolicy *policy);

int ownership_policy_set_wildcard(OwnershipPolicy *policy, bool deny, uint64_t priority);
int ownership_policy_add_prefix(OwnershipPolicy *policy, const char *prefix, bool deny, uint64_t priority);
int ownership_policy_add_name(OwnershipPolicy *policy, const char *name, bool deny, uint64_t priority);

int ownership_policy_check_allowed(OwnershipPolicy *policy, const char *name);

void connection_policy_init(ConnectionPolicy *policy);
void connection_policy_deinit(ConnectionPolicy *policy);

bool connection_policy_is_empty(ConnectionPolicy *policy);

int connection_policy_set_wildcard(ConnectionPolicy *policy, bool deny, uint64_t priority);
int connection_policy_add_uid(ConnectionPolicy *policy, uid_t uid, bool deny, uint64_t priority);
int connection_policy_add_gid(ConnectionPolicy *policy, gid_t gid, bool deny, uint64_t priority);

int connection_policy_check_allowed(ConnectionPolicy *policy, uid_t uid, gid_t *gids, size_t n_gids);

void transmission_policy_init(TransmissionPolicy *policy);
void transmission_policy_deinit(TransmissionPolicy *policy);

bool transmission_policy_is_empty(TransmissionPolicy *policy);

int transmission_policy_add_entry(TransmissionPolicy *policy,
                                  const char *name, const char *interface, const char *method, const char *path, int type,
                                  bool deny, uint64_t priority);

int transmission_policy_check_allowed(TransmissionPolicy *policy, NameOwner *subject,
                                      const char *interface, const char *method, const char *path, int type);

void policy_init(Policy *policy);
void policy_deinit(Policy *policy);

bool policy_is_empty(Policy *policy);

void policy_registry_init(PolicyRegistry *registry);
void policy_registry_deinit(PolicyRegistry *registry);

bool policy_registry_needs_groups(PolicyRegistry *registry);

int policy_registry_get_policy_by_uid(PolicyRegistry *registry, Policy **policyp, uid_t uid);
int policy_registry_get_policy_by_gid(PolicyRegistry *registry, Policy **policyp, gid_t gid);
int policy_registry_instantiate_policy(PolicyRegistry *registry, uid_t uid, gid_t *gids, size_t n_gids, Policy *policy);

int policy_registry_from_file(PolicyRegistry *registry, const char *filename, PolicyParser *parent);
