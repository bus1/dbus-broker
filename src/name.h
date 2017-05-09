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
typedef struct NameOwnership NameOwnership;
typedef struct NameEntry NameEntry;
typedef struct NameRegistry NameRegistry;
typedef struct Peer Peer;

enum {
        _NAME_E_SUCCESS,

        NAME_E_QUOTA,

        NAME_E_NOT_FOUND,
        NAME_E_NOT_OWNER,

        NAME_E_IN_QUEUE,
        NAME_E_EXISTS,
        NAME_E_ALREADY_OWNER,
};

struct NameChange {
        NameEntry *name;
        Peer *old_owner;
        Peer *new_owner;
};

struct NameOwnership {
        Peer *peer;
        NameEntry *entry;
        CRBNode rb;
        CList entry_link;
        uint64_t flags;
};

struct NameEntry {
        _Atomic unsigned long n_refs;
        NameRegistry *registry;

        Activation *activation;

        MatchRegistry matches;

        CList owners;
        CRBNode rb;
        const char name[];
};

struct NameRegistry {
        /* XXX: use a trie instead? */
        CRBTree entries;
};

void name_change_init(NameChange *change);
void name_change_deinit(NameChange *change);

void name_owner_release(NameOwnership *owner, NameChange *change);
bool name_owner_is_primary(NameOwnership *owner);

int name_entry_get(NameEntry **entryp, NameRegistry *registry, const char *name);
void name_entry_free(_Atomic unsigned long *n_refs, void *userpointer);

bool name_entry_is_owned(NameEntry *entry);

NameEntry *name_registry_find_entry(NameRegistry *registry, const char *name);
Peer *name_registry_resolve_name(NameRegistry *registry, const char *name);

void name_registry_init(NameRegistry *registry);
void name_registry_deinit(NameRegistry *registry);

int name_registry_request_name(NameRegistry *registry, Peer *peer, const char *name, uint32_t flags, NameChange *change);
int name_registry_release_name(NameRegistry *registry, Peer *peer, const char *name, NameChange *change);

static inline NameEntry *name_entry_ref(NameEntry *entry) {
        if (entry)
                c_ref_inc(&entry->n_refs);

        return entry;
}

static inline NameEntry *name_entry_unref(NameEntry *entry) {
        if (entry)
                c_ref_dec(&entry->n_refs, name_entry_free, NULL);

        return NULL;
}

C_DEFINE_CLEANUP(NameEntry *, name_entry_unref);
