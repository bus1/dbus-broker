#pragma once

/*
 * Name Registry
 */

#include <c-macro.h>
#include <c-ref.h>
#include <stdlib.h>
#include "match.h"

typedef struct Activation Activation;
typedef struct NameChange NameChange;
typedef struct Name Name;
typedef struct NameOwnership NameOwnership;
typedef struct NameOwner NameOwner;
typedef struct NameRegistry NameRegistry;

enum {
        _NAME_E_SUCCESS,

        NAME_E_NOT_FOUND,
        NAME_E_NOT_OWNER,

        NAME_E_OWNER_NEW,
        NAME_E_OWNER_UPDATED,
        NAME_E_IN_QUEUE_NEW,
        NAME_E_IN_QUEUE_UPDATED,
        NAME_E_EXISTS,
};

struct NameChange {
        Name *name;
        NameOwner *old_owner;
        NameOwner *new_owner;
};

struct NameOwnership {
        NameOwner *owner;
        Name *name;
        CRBNode owner_node;
        CList name_link;
        uint64_t flags;
};

struct Name {
        _Atomic unsigned long n_refs;
        NameRegistry *registry;

        Activation *activation;

        MatchRegistry matches;

        CList ownership_list;
        CRBNode registry_node;
        const char name[];
};

struct NameRegistry {
        /* XXX: use a trie instead? */
        CRBTree name_tree;
};

struct NameOwner {
        CRBTree ownership_tree;
};

void name_change_init(NameChange *change);
void name_change_deinit(NameChange *change);

void name_ownership_release(NameOwnership *owner, NameChange *change);
bool name_ownership_is_primary(NameOwnership *owner);

void name_free(_Atomic unsigned long *n_refs, void *userpointer);

bool name_is_owned(Name *name);

void name_owner_init(NameOwner *owner);
void name_owner_deinit(NameOwner *owner);

void name_registry_init(NameRegistry *registry);
void name_registry_deinit(NameRegistry *registry);

int name_registry_ref_name(NameRegistry *registry, Name **namep, const char *name_str);

Name *name_registry_find_name(NameRegistry *registry, const char *name_str);
NameOwner *name_registry_resolve_owner(NameRegistry *registry, const char *name_str);

int name_registry_request_name(NameRegistry *registry, NameOwner *owner, const char *name_str, uint32_t flags, NameChange *change);
int name_registry_release_name(NameRegistry *registry, NameOwner *owner, const char *name_str, NameChange *change);

static inline Name *name_ref(Name *name) {
        if (name)
                c_ref_inc(&name->n_refs);

        return name;
}

static inline Name *name_unref(Name *name) {
        if (name)
                c_ref_dec(&name->n_refs, name_free, NULL);

        return NULL;
}

C_DEFINE_CLEANUP(Name *, name_unref);
