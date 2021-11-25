/*
 * Reply Registry
 */

#include <c-list.h>
#include <c-rbtree.h>
#include <c-stdaux.h>
#include <stdlib.h>
#include "bus/reply.h"
#include "util/error.h"
#include "util/user.h"

typedef struct ReplySlotKey ReplySlotKey;

struct ReplySlotKey {
        uint64_t id;
        uint32_t serial;
};

static int reply_slot_compare(CRBTree *tree, void *k, CRBNode *rb) {
        ReplySlot *slot = c_container_of(rb, ReplySlot, registry_node);
        ReplySlotKey *key = k;

        if (key->id < slot->id)
                return -1;
        if (key->id > slot->id)
                return 1;

        if (key->serial < slot->serial)
                return -1;
        if (key->serial > slot->serial)
                return 1;

        return 0;
}

int reply_slot_new(ReplySlot **replyp, ReplyRegistry *registry, ReplyOwner *owner, User *user, User *actor, uint64_t id, uint32_t serial) {
        ReplySlot *reply;
        CRBNode **slot, *parent;
        ReplySlotKey key = {
                .id = id,
                .serial = serial,
        };
        int r;

        slot = c_rbtree_find_slot(&registry->reply_tree, reply_slot_compare, &key, &parent);
        if (!slot)
                return REPLY_E_EXISTS;

        reply = calloc(1, sizeof(*reply));
        if (!reply)
                return error_origin(-ENOMEM);

        reply->registry = registry;
        reply->owner = owner;
        reply->charge = (UserCharge)USER_CHARGE_INIT;
        reply->registry_node = (CRBNode)C_RBNODE_INIT(reply->registry_node);
        reply->owner_link = (CList)C_LIST_INIT(reply->owner_link);
        reply->id = id;
        reply->serial = serial;

        r = user_charge(user, &reply->charge, actor, USER_SLOT_OBJECTS, 1);
        if (r)
                return (r == USER_E_QUOTA) ? REPLY_E_QUOTA : error_fold(r);

        c_rbtree_add(&registry->reply_tree, parent, slot, &reply->registry_node);
        c_list_link_tail(&owner->reply_list, &reply->owner_link);

        *replyp = reply;

        return 0;
}

ReplySlot *reply_slot_free(ReplySlot *slot) {
        if (!slot)
                return NULL;

        user_charge_deinit(&slot->charge);
        c_list_unlink(&slot->owner_link);
        c_rbnode_unlink(&slot->registry_node);

        free(slot);

        return NULL;
}

ReplySlot *reply_slot_get_by_id(ReplyRegistry *registry, uint64_t id, uint32_t serial) {
        ReplySlotKey key = {
                .id = id,
                .serial = serial,
        };

        return c_rbtree_find_entry(&registry->reply_tree, reply_slot_compare, &key, ReplySlot, registry_node);
}

void reply_registry_init(ReplyRegistry *registry) {
        *registry = (ReplyRegistry)REPLY_REGISTRY_INIT;
}

void reply_registry_deinit(ReplyRegistry *registry) {
        c_assert(c_rbtree_is_empty(&registry->reply_tree));
}

void reply_owner_init(ReplyOwner *owner) {
        *owner = (ReplyOwner)REPLY_OWNER_INIT(*owner);
}

void reply_owner_deinit(ReplyOwner *owner) {
        c_assert(c_list_is_empty(&owner->reply_list));
}

void reply_owner_get_stats(ReplyOwner *owner, unsigned int *n_objectsp) {
        ReplySlot *reply;
        unsigned int n_objects = 0;

        c_list_for_each_entry(reply, &owner->reply_list, owner_link)
                n_objects += reply->charge.charge;

        *n_objectsp = n_objects;
}
