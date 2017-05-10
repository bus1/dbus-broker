#pragma once

/*
 * D-Bus Match Rules
 */

#include <c-list.h>
#include <c-rbtree.h>
#include <stdlib.h>

typedef struct MatchFilter MatchFilter;
typedef struct MatchRuleKeys MatchRuleKeys;
typedef struct MatchRule MatchRule;
typedef struct MatchRegistry MatchRegistry;
typedef struct MatchOwner MatchOwner;

enum {
        _MATCH_E_SUCCESS,

        MATCH_E_INVALID,
        MATCH_E_NOT_FOUND,
};

struct MatchFilter {
        uint8_t type;
        uint64_t destination;
        const char *interface;
        const char *member;
        const char *path;
        const char *args[64];
        const char *argpaths[64];
};

struct MatchRuleKeys {
        const char *sender;
        MatchFilter filter;
        bool eavesdrop : 1;
        const char *path_namespace;
        const char *arg0namespace;
};

struct MatchRule {
        unsigned long int n_user_refs;

        MatchRegistry *registry;
        MatchOwner *owner;

        CList registry_link;
        CRBNode owner_node;

        MatchRuleKeys keys;

        char buffer[];
};

struct MatchRegistry {
        CList rule_list;
};

struct MatchOwner {
        CRBTree rule_tree;
};

int match_rule_new(MatchRule **rulep, MatchOwner *owner, const char *rule_string);
MatchRule *match_rule_free(MatchRule *rule);
MatchRule *match_rule_user_ref(MatchRule *rule);
MatchRule *match_rule_user_unref(MatchRule *rule);

void match_rule_link(MatchRule *rule, MatchRegistry *registry);
int match_rule_get(MatchRule **rulep, MatchOwner *owner, const char *rule_string);

MatchRule *match_rule_next(MatchRegistry *registry, MatchRule *rule, MatchFilter *filter);

#define MATCH_REGISTRY_INIT(_x) {                               \
                .rule_list = (CList)C_LIST_INIT((_x).rule_list) \
        }

void match_registry_init(MatchRegistry *registry);
void match_registry_deinit(MatchRegistry *registry);

void match_owner_init(MatchOwner *owner);
void match_owner_deinit(MatchOwner *owner);

C_DEFINE_CLEANUP(MatchRule *, match_rule_free);
C_DEFINE_CLEANUP(MatchRule *, match_rule_user_unref);
