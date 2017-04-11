#pragma once

/*
 * D-Bus Match Rules
 */

#include <c-list.h>
#include <c-rbtree.h>
#include <c-ref.h>
#include <stdlib.h>

typedef struct MatchFilter MatchFilter;
typedef struct MatchRuleKeys MatchRuleKeys;
typedef struct MatchRule MatchRule;
typedef struct MatchRegistry MatchRegistry;
typedef struct Peer Peer;

struct MatchFilter {
        uint8_t type;
        const char *sender; /* XXX: make implicit */
        uint64_t destination;
        const char *interface;
        const char *member;
        const char *path;
        const char *args[64];
};

struct MatchRuleKeys {
        MatchFilter filter;
        bool eavesdrop : 1;
        const char *path_namespace;
        const char *argpaths[64];
        const char *arg0namespace;
};

struct MatchRule {
        _Atomic unsigned long n_refs;

        Peer *peer;

        CList link_registry;
        CRBNode rb_peer;

        MatchRuleKeys keys;

        char buffer[];
};

struct MatchRegistry {
        CList rules;
};

int match_rule_new(MatchRule **rulep, Peer *peer, const char *rule_string);
void match_rule_free(_Atomic unsigned long *n_refs, void *userdata);

void match_rule_link(MatchRule *rule, MatchRegistry *registry);
int match_rule_get(MatchRule **rulep, Peer *peer, const char *rule_string);

MatchRule *match_rule_next(MatchRegistry *registry, MatchRule *rule, MatchFilter *filter);

void match_registry_init(MatchRegistry *registry);
void match_registry_deinit(MatchRegistry *registry);

static inline MatchRule *match_rule_ref(MatchRule *rule) {
        if (rule)
                c_ref_inc(&rule->n_refs);
        return rule;
}

static inline MatchRule *match_rule_unref(MatchRule *rule) {
        if (rule)
                c_ref_dec(&rule->n_refs, match_rule_free, NULL);
        return NULL;
}

C_DEFINE_CLEANUP(MatchRule *, match_rule_unref);
