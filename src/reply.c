/*
 * Reply Registry
 */

#include <c-list.h>
#include <c-macro.h>
#include <c-rbtree.h>
#include <stdlib.h>
#include "peer.h"
#include "reply.h"

typedef struct ReplySlotKey ReplySlotKey;

struct ReplySlotKey {
        uint64_t id;
        uint32_t serial;
};

void reply_registry_init(ReplyRegistry *registry) {
        *registry = (ReplyRegistry){};
}

void reply_registry_deinit(ReplyRegistry *registry) {
        assert(!registry->slots.root);
}

static int reply_slot_compare(CRBTree *tree, void *k, CRBNode *rb) {
        ReplySlot *slot = c_container_of(rb, ReplySlot, rb);
        ReplySlotKey *key = k;

        if (slot->sender->id < key->id)
                return -1;
        if (slot->sender->id > key->id)
                return 1;

        if (slot->serial < key->serial)
                return -1;
        if (slot->serial > key->serial)
                return 1;

        return 0;
}

int reply_slot_new(ReplySlot **replyp, ReplyRegistry *registry, Peer *sender, uint32_t serial) {
        ReplySlot *reply;
        CRBNode **slot, *parent;
        ReplySlotKey key = {
                .id = sender->id,
                .serial = serial,
        };

        slot = c_rbtree_find_slot(&registry->slots, reply_slot_compare, &key, &parent);
        if (!slot)
                return -EEXIST;

        reply = calloc(1, sizeof(*reply));
        if (!reply)
                return -ENOMEM;

        reply->registry = registry;
        c_rbnode_init(&reply->rb);
        reply->link = (CList)C_LIST_INIT(reply->link);
        reply->sender = sender;
        reply->serial = serial;

        c_rbtree_add(&registry->slots, parent, slot, &reply->rb);
        c_list_link_tail(&sender->replies_incoming, &reply->link);

        *replyp = reply;

        return 0;
}

ReplySlot *reply_slot_free(ReplySlot *slot) {
        if (!slot)
                return NULL;

        c_list_unlink(&slot->link);
        c_rbtree_remove(&slot->registry->slots, &slot->rb);

        free(slot);

        return NULL;
}

ReplySlot *reply_slot_get_by_id(ReplyRegistry *registry, uint64_t id, uint32_t serial) {
        ReplySlotKey key = {
                .id = id,
                .serial = serial,
        };

        return c_rbtree_find_entry(&registry->slots, reply_slot_compare, &key, ReplySlot, rb);
}
