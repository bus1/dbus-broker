#pragma once

/*
 * D-Bus Match Rules
 */

#include <c-list.h>
#include <c-rbtree.h>
#include <c-ref.h>
#include <stdlib.h>

typedef struct DBusMatchFilter DBusMatchFilter;
typedef struct DBusMatchRuleKeys DBusMatchRuleKeys;
typedef struct DBusMatchRule DBusMatchRule;
typedef struct DBusMatchRegistry DBusMatchRegistry;
typedef struct Peer Peer;

struct DBusMatchFilter {
        uint8_t type;
        const char *sender; /* XXX: make implicit */
        const char *destination; /* XXX: make uint64_t */
        const char *interface;
        const char *member;
        const char *path;
        const char *args[64];
};

struct DBusMatchRuleKeys {
        DBusMatchFilter filter;
        bool eavesdrop : 1;
        const char *path_namespace;
        const char *argpaths[64];
        const char *arg0namespace;
};

struct DBusMatchRule {
        _Atomic unsigned long n_refs;

        Peer *peer;

        CList link_registry;
        CRBNode rb_peer;

        DBusMatchRuleKeys keys;

        char buffer[];
};

struct DBusMatchRegistry {
        CList rules;
};

int dbus_match_rule_new(DBusMatchRule **rulep, Peer *peer, const char *rule_string);
void dbus_match_rule_free(_Atomic unsigned long *n_refs, void *userdata);

void dbus_match_rule_link(DBusMatchRule *rule, DBusMatchRegistry *registry);
int dbus_match_rule_get(DBusMatchRule **rulep, Peer *peer, const char *rule_string);

DBusMatchRule *dbus_match_rule_next(DBusMatchRegistry *registry, DBusMatchRule *rule, DBusMatchFilter *filter);

void dbus_match_registry_init(DBusMatchRegistry *registry);
void dbus_match_registry_deinit(DBusMatchRegistry *registry);

static inline DBusMatchRule *dbus_match_rule_ref(DBusMatchRule *rule) {
        if (rule)
                c_ref_inc(&rule->n_refs);
        return rule;
}

static inline DBusMatchRule *dbus_match_rule_unref(DBusMatchRule *rule) {
        if (rule)
                c_ref_dec(&rule->n_refs, dbus_match_rule_free, NULL);
        return NULL;
}

C_DEFINE_CLEANUP(DBusMatchRule *, dbus_match_rule_unref);
