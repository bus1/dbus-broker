#pragma once

/*
 * D-Bus Match Rules
 */

#include <c-list.h>
#include <c-rbtree.h>
#include <stdlib.h>
#include "dbus/address.h"
#include "util/user.h"

typedef struct MatchFilter MatchFilter;
typedef struct MatchKeys MatchKeys;
typedef struct MatchOwner MatchOwner;
typedef struct MatchRegistry MatchRegistry;
typedef struct MatchRule MatchRule;

#define MATCH_RULE_LENGTH_MAX (1024UL) /* taken from dbus-daemon(1) */

enum {
        _MATCH_E_SUCCESS,

        MATCH_E_EOF,
        MATCH_E_INVALID,
        MATCH_E_QUOTA,
};

struct MatchFilter {
        uint8_t type;
        uint64_t destination;
        uint64_t sender;
        const char *interface;
        const char *member;
        const char *path;
        const char *args[64];
        size_t n_args;
        const char *argpaths[64];
        size_t n_argpaths;
};

#define MATCH_FILTER_INIT {                             \
                .type = DBUS_MESSAGE_TYPE_INVALID,      \
                .destination = ADDRESS_ID_INVALID,      \
                .sender = ADDRESS_ID_INVALID,           \
        }

struct MatchKeys {
        MatchFilter filter;
        const char *destination;
        const char *sender;
        const char *path_namespace;
        const char *arg0namespace;

        char buffer[];
};

#define MATCH_KEYS_NULL {                                                       \
                .filter = MATCH_FILTER_INIT,                                    \
        }

struct MatchRule {
        unsigned long int n_user_refs;
        MatchRegistry *registry;
        MatchOwner *owner;
        CList registry_link;
        CRBNode owner_node;

        UserCharge charge[2];
        MatchKeys keys;
        /* @keys must be last, as it contains a VLA */
};

#define MATCH_RULE_NULL(_x) {                                                   \
                .registry_link = C_LIST_INIT((_x).registry_link),               \
                .owner_node = C_RBNODE_INIT((_x).owner_node),                   \
                .charge = { USER_CHARGE_INIT, USER_CHARGE_INIT },               \
                .keys = MATCH_KEYS_NULL,                                        \
        }

struct MatchOwner {
        CRBTree rule_tree;
};

#define MATCH_OWNER_INIT {                      \
                .rule_tree = C_RBTREE_INIT,     \
        }

struct MatchRegistry {
        CList rule_list;
        CList monitor_list;
};

#define MATCH_REGISTRY_INIT(_x) {                                               \
                .rule_list = (CList)C_LIST_INIT((_x).rule_list),                \
                .monitor_list = (CList)C_LIST_INIT((_x).monitor_list),          \
        }

/* rules */

MatchRule *match_rule_user_ref(MatchRule *rule);
MatchRule *match_rule_user_unref(MatchRule *rule);

void match_rule_link(MatchRule *rule, MatchRegistry *registry, bool monitor);
void match_rule_unlink(MatchRule *rule);

MatchRule *match_rule_next_match(MatchRegistry *registry, MatchRule *rule, MatchFilter *filter);
MatchRule *match_rule_next_monitor_match(MatchRegistry *registry, MatchRule *rule, MatchFilter *filter);

C_DEFINE_CLEANUP(MatchRule *, match_rule_user_unref);

/* owners */

void match_owner_init(MatchOwner *owner);
void match_owner_deinit(MatchOwner *owner);

void match_owner_move(MatchOwner *to, MatchOwner *from);
int match_owner_ref_rule(MatchOwner *owner, MatchRule **rulep, User *user, const char *rule_string);
int match_owner_find_rule(MatchOwner *owner, MatchRule **rulep, const char *rule_string);

/* registry */

void match_registry_init(MatchRegistry *registry);
void match_registry_deinit(MatchRegistry *registry);
