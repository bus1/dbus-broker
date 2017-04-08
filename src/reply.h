#pragma once

/*
 * Reply Registry
 */

#include <c-list.h>
#include <c-macro.h>
#include <c-rbtree.h>
#include <stdlib.h>

typedef struct Peer Peer;
typedef struct ReplySlot ReplySlot;
typedef struct ReplyRegistry ReplyRegistry;

struct ReplySlot {
        ReplyRegistry *registry;
        Peer *sender;
        uint32_t serial;
        CRBNode rb;
        CList link;
};

struct ReplyRegistry {
        CRBTree slots;
};

void reply_registry_init(ReplyRegistry *registry);
void reply_registry_deinit(ReplyRegistry *registry);

int reply_slot_new(ReplySlot **replyp, ReplyRegistry *registry, Peer *sender, uint32_t serial);
ReplySlot *reply_slot_free(ReplySlot *slot);

ReplySlot *reply_slot_get_by_id(ReplyRegistry *registry, uint64_t id, uint32_t serial);

C_DEFINE_CLEANUP(ReplySlot *, reply_slot_free);
