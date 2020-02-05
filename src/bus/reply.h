#pragma once

/*
 * Reply Registry
 */

#include <c-list.h>
#include <c-rbtree.h>
#include <c-stdaux.h>
#include <stdlib.h>
#include "util/user.h"

typedef struct ReplySlot ReplySlot;
typedef struct ReplyRegistry ReplyRegistry;
typedef struct ReplyOwner ReplyOwner;

enum {
        _REPLY_E_SUCCESS,

        REPLY_E_EXISTS,
        REPLY_E_QUOTA,
};

struct ReplySlot {
        ReplyRegistry *registry;
        ReplyOwner *owner;
        UserCharge charge;
        uint64_t id;
        uint32_t serial;
        CRBNode registry_node;
        CList owner_link;
};

struct ReplyRegistry {
        CRBTree reply_tree;
};

#define REPLY_REGISTRY_INIT {                   \
                .reply_tree = C_RBTREE_INIT,    \
        }

struct ReplyOwner {
        CList reply_list;
};

#define REPLY_OWNER_INIT(_x) {                                  \
                .reply_list = C_LIST_INIT((_x).reply_list),     \
        }

int reply_slot_new(ReplySlot **replyp, ReplyRegistry *registry, ReplyOwner *owner, User *user, User *actor, uint64_t id, uint32_t serial);
ReplySlot *reply_slot_free(ReplySlot *slot);

ReplySlot *reply_slot_get_by_id(ReplyRegistry *registry, uint64_t id, uint32_t serial);

void reply_registry_init(ReplyRegistry *registry);
void reply_registry_deinit(ReplyRegistry *registry);

void reply_owner_init(ReplyOwner *owner);
void reply_owner_deinit(ReplyOwner *owner);

void reply_owner_get_stats(ReplyOwner *owner, unsigned int *n_objectsp);

C_DEFINE_CLEANUP(ReplySlot *, reply_slot_free);
