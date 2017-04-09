#pragma once

/*
 * Name Registry
 */

#include <c-macro.h>
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
        NameRegistry *registry;
        CList owners;
        CRBNode rb;
        const char name[];
};

struct NameRegistry {
        /* XXX: use a trie instead? */
        CRBTree entries;
};

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

NameEntry *name_registry_find_entry(NameRegistry *registry, const char *name);
Peer *name_registry_resolve_name(NameRegistry *registry, const char *name);
