#pragma once

/*
 * D-Bus Match Rules
 */

#include <c-list.h>
#include <c-rbtree.h>
#include <c-stdaux.h>
#include <stdlib.h>
#include "dbus/address.h"
#include "util/user.h"

typedef struct MatchCounters MatchCounters;
typedef struct MatchFilter MatchFilter;
typedef struct MatchKeys MatchKeys;
typedef struct MatchOwner MatchOwner;
typedef struct MatchRegistryByKeys MatchRegistryByKeys;
typedef struct MatchRegistryByMember MatchRegistryByMember;
typedef struct MatchRegistryByInterface MatchRegistryByInterface;
typedef struct MatchRegistryByPath MatchRegistryByPath;
typedef struct MatchRegistry MatchRegistry;
typedef struct MatchRule MatchRule;
typedef struct MessageMetadata MessageMetadata;

#define MATCH_RULE_LENGTH_MAX (1024UL) /* taken from dbus-daemon(1) */

enum {
        _MATCH_E_SUCCESS,

        MATCH_E_EOF,
        MATCH_E_INVALID,
        MATCH_E_QUOTA,
};

struct MatchFilter {
        uint8_t type;
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
                .sender = ADDRESS_ID_INVALID,           \
        }

struct MatchKeys {
        MatchFilter filter;
        const char *destination;
        const char *sender;
        const char *path_namespace;
        const char *arg0namespace;

        size_t n_buffer;
        char buffer[];
};

#define MATCH_KEYS_NULL {                                                       \
                .filter = MATCH_FILTER_INIT,                                    \
        }

struct MatchRule {
        unsigned long int n_user_refs;
        MatchRegistryByKeys *registry_by_keys;
        CList registry_link;
        MatchRegistry *registry;
        MatchOwner *owner;
        CRBNode owner_node;
        MatchCounters *counters;

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
        size_t n_owner_subscriptions;
        CRBTree rule_tree;
        CList destinations_link;
};

#define MATCH_OWNER_INIT(_x) {                                                  \
                .rule_tree = C_RBTREE_INIT,                                     \
                .destinations_link = C_LIST_INIT((_x).destinations_link),       \
        }

struct MatchRegistryByKeys {
        unsigned long n_refs;
        CList rule_list;
        MatchRegistryByMember *registry_by_member;
        CRBNode registry_node;
        MatchKeys keys;
        /* @keys must be last, as it contains a VLA */
};

#define MATCH_REGISTRY_BY_KEYS_INIT(_x) {                               \
                .n_refs = 1,                                            \
                .rule_list = C_LIST_INIT((_x).rule_list),               \
                .registry_node = C_RBNODE_INIT((_x).registry_node),     \
                .keys = MATCH_KEYS_NULL,                                \
        }

struct MatchRegistryByMember {
        unsigned long n_refs;
        CRBTree keys_tree;
        MatchRegistryByInterface *registry_by_interface;
        CRBNode registry_node;
        char member[];
};

#define MATCH_REGISTRY_BY_MEMBER_INIT(_x) {                             \
                .n_refs = 1,                                            \
                .keys_tree = C_RBTREE_INIT,                             \
                .registry_node = C_RBNODE_INIT((_x).registry_node),     \
        }

struct MatchRegistryByInterface {
        unsigned long n_refs;
        CRBTree member_tree;
        MatchRegistryByPath *registry_by_path;
        CRBNode registry_node;
        char interface[];
};

#define MATCH_REGISTRY_BY_INTERFACE_INIT(_x) {                          \
                .n_refs = 1,                                            \
                .member_tree = C_RBTREE_INIT,                           \
                .registry_node = C_RBNODE_INIT((_x).registry_node),     \
        }

struct MatchRegistryByPath {
        unsigned long n_refs;
        CRBTree interface_tree;
        CRBNode registry_node;
        char path[];
};

#define MATCH_REGISTRY_BY_PATH_INIT(_x) {                               \
                .n_refs = 1,                                            \
                .interface_tree = C_RBTREE_INIT,                        \
                .registry_node = C_RBNODE_INIT((_x).registry_node),     \
        }

struct MatchRegistry {
        CRBTree subscription_tree;
        CRBTree monitor_tree;
};

#define MATCH_REGISTRY_INIT(_x) {                       \
                .subscription_tree = C_RBTREE_INIT,     \
                .monitor_tree = C_RBTREE_INIT,          \
        }

struct MatchCounters {
        size_t n_subscriptions;
        size_t n_subscriptions_peak;
        size_t n_owner_subscriptions_peak;
};

#define MATCH_COUNTERS_INIT {}

/* rules */

MatchRule *match_rule_user_ref(MatchRule *rule);
MatchRule *match_rule_user_unref(MatchRule *rule);

int match_rule_link(MatchRule *rule, MatchCounters *counters, MatchRegistry *registry, bool monitor);
void match_rule_unlink(MatchRule *rule);

C_DEFINE_CLEANUP(MatchRule *, match_rule_user_unref);

/* owners */

void match_owner_init(MatchOwner *owner);
void match_owner_deinit(MatchOwner *owner);

void match_owner_get_stats(MatchOwner *owner, unsigned int *n_bytesp, unsigned int *n_matchesp);
void match_owner_move(MatchOwner *to, MatchOwner *from);
int match_owner_ref_rule(MatchOwner *owner, MatchRule **rulep, User *user, const char *rule_string, bool allow_eavesdrop);
int match_owner_find_rule(MatchOwner *owner, MatchRule **rulep, const char *rule_string);

/* registry */

void match_registry_init(MatchRegistry *registry);
void match_registry_deinit(MatchRegistry *registry);

void match_registry_get_subscribers(MatchRegistry *matches, CList *destinations, MessageMetadata *metadata);
void match_registry_get_monitors(MatchRegistry *matches, CList *destinations, MessageMetadata *metadata);

void match_registry_flush(MatchRegistry *registry);
