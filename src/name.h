#pragma once

/*
 * Name Registry
 */

#include <c-macro.h>
#include <c-ref.h>
#include <stdlib.h>
#include "peer.h"

typedef struct NameOwner NameOwner;
typedef struct NameEntry NameEntry;
typedef struct NameRegistry NameRegistry;

struct NameOwner {
        Peer *peer;
        NameEntry *entry;
        CRBNode rb;
        CList entry_link;
        uint64_t flags;
};

struct NameEntry {
        _Atomic unsigned long n_refs;
        NameRegistry *registry;
        MatchRegistry matches;
        CList owners;
        CRBNode rb;
        const char name[];
};

struct NameRegistry {
        /* XXX: use a trie instead? */
        CRBTree entries;
};

NameOwner *name_owner_free(NameOwner *owner);

int name_entry_get(NameEntry **entryp, NameRegistry *registry, const char *name);
void name_entry_free(_Atomic unsigned long *n_refs, void *userpointer);

NameEntry *name_registry_find_entry(NameRegistry *registry, const char *name);
Peer *name_registry_resolve_name(NameRegistry *registry, const char *name);

void name_registry_init(NameRegistry *registry);
void name_registry_deinit(NameRegistry *registry);

int name_registry_request_name(NameRegistry *registry,
                               Peer *peer,
                               const char *name,
                               uint32_t flags,
                               uint32_t *replyp);
void name_registry_release_name(NameRegistry *registry,
                                Peer *peer,
                                const char *name,
                                uint32_t *replyp);

void name_registry_release_all_names(NameRegistry *registry, Peer *peer);

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
