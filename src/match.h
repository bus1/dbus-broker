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
typedef struct Peer Peer;

enum {
        _MATCH_E_SUCCESS,

        MATCH_E_INVALID,
        MATCH_E_NOT_FOUND,
        MATCH_E_QUOTA,
};

struct MatchFilter {
        uint8_t type;
        const char *destination;
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
        unsigned int n_user_refs;

        Peer *peer;
        MatchRegistry *registry;

        CList link_registry;
        CRBNode rb_peer;

        MatchRuleKeys keys;

        char buffer[];
};

struct MatchRegistry {
        CList rules;
};

int match_rule_new(MatchRule **rulep, Peer *peer, const char *rule_string);
MatchRule *match_rule_free(MatchRule *rule);
MatchRule *match_rule_user_ref(MatchRule *rule);
MatchRule *match_rule_user_unref(MatchRule *rule);

void match_rule_link(MatchRule *rule, MatchRegistry *registry);
int match_rule_get(MatchRule **rulep, Peer *peer, const char *rule_string);

MatchRule *match_rule_next(MatchRegistry *registry, MatchRule *rule, MatchFilter *filter);

void match_registry_init(MatchRegistry *registry);
void match_registry_deinit(MatchRegistry *registry);

C_DEFINE_CLEANUP(MatchRule *, match_rule_free);
