#pragma once

/*
 * Name Registry
 */

#include <c-macro.h>
#include <stdlib.h>
#include "peer.h"

/* from the spec */
#define DBUS_NAME_FLAG_ALLOW_REPLACEMENT        (1ULL << 0)
#define DBUS_NAME_FLAG_REPLACE_EXISTING         (1ULL << 1)
#define DBUS_NAME_FLAG_DO_NOT_QUEUE             (1ULL << 2)

#define DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER   (1)
#define DBUS_REQUEST_NAME_REPLY_IN_QUEUE        (2)
#define DBUS_REQUEST_NAME_REPLY_EXISTS          (3)
#define DBUS_REQUEST_NAME_REPLY_ALREADY_OWNER   (4)

#define DBUS_RELEASE_NAME_REPLY_RELEASED        (1)
#define DBUS_RELEASE_NAME_REPLY_NON_EXISTENT    (2)
#define DBUS_RELEASE_NAME_REPLY_NOT_OWNER       (3)

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
