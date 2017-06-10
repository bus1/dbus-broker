#pragma once

/*
 * D-Bus Policy
 */

#include <c-rbtree.h>
#include <stdlib.h>

enum {
        _POLICY_E_SUCCESS,

        POLICY_E_ACCESS_DENIED,
        POLICY_E_INVALID_XML,
};

typedef struct ConnectionPolicy ConnectionPolicy;
typedef struct ConnectionPolicyEntry ConnectionPolicyEntry;
typedef struct OwnershipPolicy OwnershipPolicy;
typedef struct OwnershipPolicyEntry OwnershipPolicyEntry;
typedef struct PolicyDecision PolicyDecision;

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
        PolicyDecision uid_wildcard;
        CRBTree gid_tree;
        PolicyDecision gid_wildcard;
};

struct ConnectionPolicyEntry {
        CRBTree *policy;
        PolicyDecision decision;
        CRBNode rb;
        uid_t uid;
};

void ownership_policy_init(OwnershipPolicy *policy);
void ownership_policy_deinit(OwnershipPolicy *policy);

int ownership_policy_set_wildcard(OwnershipPolicy *policy, bool deny, uint64_t priority);
int ownership_policy_add_prefix(OwnershipPolicy *policy, const char *prefix, bool deny, uint64_t priority);
int ownership_policy_add_name(OwnershipPolicy *policy, const char *name, bool deny, uint64_t priority);

int ownership_policy_check_allowed(OwnershipPolicy *policy, const char *name);

void connection_policy_init(ConnectionPolicy *policy);
void connection_policy_deinit(ConnectionPolicy *policy);

int connection_policy_set_uid_wildcard(ConnectionPolicy *policy, bool deny, uint64_t priority);
int connection_policy_set_gid_wildcard(ConnectionPolicy *policy, bool deny, uint64_t priority);
int connection_policy_add_uid(ConnectionPolicy *policy, uid_t uid, bool deny, uint64_t priority);
int connection_policy_add_gid(ConnectionPolicy *policy, gid_t gid, bool deny, uint64_t priority);

int connection_policy_check_allowed(ConnectionPolicy *policy, uid_t uid);

int policy_parse(void);
