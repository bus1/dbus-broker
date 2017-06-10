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

void ownership_policy_init(OwnershipPolicy *policy);
void ownership_policy_deinit(OwnershipPolicy *policy);

int ownership_policy_set_wildcard(OwnershipPolicy *policy, bool deny, uint64_t priority);
int ownership_policy_add_prefix(OwnershipPolicy *policy, const char *prefix, bool deny, uint64_t priority);
int ownership_policy_add_name(OwnershipPolicy *policy, const char *name, bool deny, uint64_t priority);

int ownership_policy_check_allowed(OwnershipPolicy *policy, const char *name);

int policy_parse(void);
