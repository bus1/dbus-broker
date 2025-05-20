#pragma once

/*
 * Name Registry
 */

#include <c-stdaux.h>
#include <stdlib.h>
#include "bus/match.h"
#include "util/ref.h"
#include "util/user.h"

typedef struct Activation Activation;
typedef struct Name Name;
typedef struct NameChange NameChange;
typedef struct NameOwner NameOwner;
typedef struct NameOwnership NameOwnership;
typedef struct NameRegistry NameRegistry;
typedef struct NameSet NameSet;
typedef struct NameSnapshot NameSnapshot;

enum {
        _NAME_E_SUCCESS,

        NAME_E_NOT_FOUND,
        NAME_E_NOT_OWNER,

        NAME_E_QUOTA,
        NAME_E_ALREADY_OWNER,
        NAME_E_IN_QUEUE,
        NAME_E_EXISTS,
};

struct NameChange {
        Name *name;
        NameOwner *old_owner;
        NameOwner *new_owner;
};

#define NAME_CHANGE_INIT {}

struct NameOwnership {
        NameOwner *owner;
        Name *name;
        CRBNode owner_node;
        CList name_link;
        uint64_t flags;
        UserCharge charge;
};

#define NAME_OWNERSHIP_NULL(_x) {                                               \
                .owner_node = C_RBNODE_INIT((_x).owner_node),                   \
                .name_link = C_LIST_INIT((_x).name_link),                       \
                .charge = USER_CHARGE_INIT,                                     \
        }

struct Name {
        _Atomic unsigned long n_refs;
        NameRegistry *registry;
        CRBNode registry_node;

        Activation *activation;
        MatchRegistry sender_matches;
        MatchRegistry name_owner_changed_matches;

        CList ownership_list;
        char name[];
};

#define NAME_INIT(_x) {                                                                                 \
                .n_refs = REF_INIT,                                                                     \
                .registry_node = C_RBNODE_INIT((_x).registry_node),                                     \
                .sender_matches = MATCH_REGISTRY_INIT((_x).sender_matches),                             \
                .name_owner_changed_matches = MATCH_REGISTRY_INIT((_x).name_owner_changed_matches),     \
                .ownership_list = C_LIST_INIT((_x).ownership_list),                                     \
        }

struct NameOwner {
        size_t n_owner_primaries;
        CRBTree ownership_tree;
};

#define NAME_OWNER_INIT {                                                       \
                .ownership_tree = C_RBTREE_INIT,                                \
        }

struct NameRegistry {
        size_t n_primaries;
        size_t n_primaries_peak;
        size_t n_owner_primaries_peak;
        CRBTree name_tree;
};

#define NAME_REGISTRY_INIT {                                                    \
                .name_tree = C_RBTREE_INIT,                                     \
        }

struct NameSnapshot {
        size_t n_names;
        Name *names[];
};

#define NAME_SNAPSHOT_NULL {}

enum {
        NAME_SET_TYPE_OWNER,
        NAME_SET_TYPE_SNAPSHOT,
        NAME_SET_TYPE_EMPTY,
};

struct NameSet {
        unsigned int type;
        union {
                NameOwner *owner;
                NameSnapshot *snapshot;
        };
};

#define NAME_SET_INIT_FROM_OWNER(_x) {                                          \
                .type = (_x) ? NAME_SET_TYPE_OWNER : NAME_SET_TYPE_EMPTY,       \
                .owner = (_x),                                                  \
        }

#define NAME_SET_INIT_FROM_SNAPSHOT(_x) {                                       \
                .type = (_x) ? NAME_SET_TYPE_SNAPSHOT : NAME_SET_TYPE_EMPTY,    \
                .snapshot = (_x),                                               \
        }

/* notifications */

void name_change_init(NameChange *change);
void name_change_deinit(NameChange *change);

/* ownerships */

void name_ownership_release(NameOwnership *owner, NameChange *change);
bool name_ownership_is_primary(NameOwnership *owner);

/* names */

void name_free(_Atomic unsigned long *n_refs, void *userdata);

/* owners */

void name_owner_init(NameOwner *owner);
void name_owner_deinit(NameOwner *owner);

void name_owner_get_stats(NameOwner *owner, unsigned int *n_objectsp);

/* registry */

void name_registry_init(NameRegistry *registry);
void name_registry_deinit(NameRegistry *registry);

void name_registry_get_activation_stats_for(NameRegistry *registry,
                                            uint64_t owner_id,
                                            unsigned int *n_bytesp,
                                            unsigned int *n_fdsp);
int name_registry_ref_name(NameRegistry *registry, Name **namep, const char *name_str);
Name *name_registry_find_name(NameRegistry *registry, const char *name_str);

int name_registry_request_name(NameRegistry *registry,
                               NameOwner *owner,
                               User *user,
                               const char *name_str,
                               uint32_t flags,
                               NameChange *change);
int name_registry_release_name(NameRegistry *registry,
                               NameOwner *owner,
                               const char *name_str,
                               NameChange *change);

/* snapshots */

int name_snapshot_new(NameSnapshot **snapshotp, NameOwner *owner);
NameSnapshot *name_snapshot_free(NameSnapshot *snapshot);

C_DEFINE_CLEANUP(NameSnapshot *, name_snapshot_free);

/* inline helpers */

static inline Name *name_ref(Name *name) {
        if (name)
                ref_inc(&name->n_refs);
        return name;
}

static inline Name *name_unref(Name *name) {
        if (name)
                ref_dec(&name->n_refs, name_free, NULL);
        return NULL;
}

static inline NameOwnership *name_primary(Name *name) {
        return c_container_of(c_list_first(&name->ownership_list), NameOwnership, name_link);
}

C_DEFINE_CLEANUP(Name *, name_unref);
