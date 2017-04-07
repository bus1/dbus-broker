#pragma once

/*
 * Name Registry
 */

#include <c-macro.h>
#include <stdlib.h>
#include "peer.h"

typedef struct NameRegistry NameRegistry;

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
Peer *name_registry_resolve_name(NameRegistry *registry, const char *name);
