/*
 * Name Registry
 */

#include <c-macro.h>
#include <c-rbtree.h>
#include <c-ref.h>
#include <c-list.h>
#include <stdlib.h>
#include "dbus/protocol.h"
#include "dbus/socket.h"
#include "driver.h"
#include "name.h"
#include "peer.h"
#include "user.h"
#include "util/error.h"

void name_change_init(NameChange *change) {
        *change = (NameChange){};
}

void name_change_deinit(NameChange *change) {
        change->name = name_unref(change->name);
        change->old_owner = NULL;
        change->new_owner = NULL;
}

/* new owner object linked into the owning peer */
static int name_ownership_new(NameOwnership **ownershipp, NameOwner *owner, Name *name, CRBNode *parent, CRBNode **slot) {
        NameOwnership *ownership;

        ownership = calloc(1, sizeof(*ownership));
        if (!ownership)
                return error_origin(-ENOMEM);

        ownership->name_link = (CList)C_LIST_INIT(ownership->name_link);
        ownership->name = name_ref(name);
        c_rbtree_add(&owner->ownership_tree, parent, slot, &ownership->owner_node);
        ownership->owner = owner;

        *ownershipp = ownership;
        return 0;
}

/* unlink from peer and entry */
static NameOwnership *name_ownership_free(NameOwnership *ownership) {
        if (!ownership)
                return NULL;

        c_rbtree_remove(&ownership->owner->ownership_tree, &ownership->owner_node);
        c_list_unlink(&ownership->name_link);
        name_unref(ownership->name);

        free(ownership);

        return NULL;
}

static int name_ownership_compare(CRBTree *tree, void *k, CRBNode *rb) {
        NameOwnership *ownership = c_container_of(rb, NameOwnership, owner_node);

        if ((Name*)k < ownership->name)
                return -1;
        if ((Name*)k > ownership->name)
                return 1;

        return 0;
}

static int name_ownership_get(NameOwnership **ownershipp, NameOwner *owner, Name *name) {
        CRBNode **slot, *parent;
        int r;

        slot = c_rbtree_find_slot(&owner->ownership_tree, name_ownership_compare, name, &parent);
        if (!slot) {
                *ownershipp = c_container_of(parent, NameOwnership, owner_node);
        } else {
                r = name_ownership_new(ownershipp, owner, name, parent, slot);
                if (r)
                        return error_trace(r);
        }

        return 0;
}

bool name_ownership_is_primary(NameOwnership *ownership) {
        return (c_list_first(&ownership->name->ownership_list) == &ownership->name_link);
}

static int name_ownership_update(NameOwnership *ownership, uint32_t flags, NameChange *change) {
        Name *name = ownership->name;
        NameOwnership *primary;
        int r;

        assert(!change->name);
        assert(!change->old_owner);
        assert(!change->new_owner);

        primary = c_container_of(c_list_first(&name->ownership_list), NameOwnership, name_link);
        if (primary == ownership) {
                /* we are already the primary owner */
                ownership->flags = flags;
                r =  0;
        } else if (!primary) {
                /* there is no primary owner */
                change->name = name_ref(name);
                change->new_owner = ownership->owner;
                change->old_owner = NULL;

                /* @owner cannot already be linked */
                c_list_link_front(&name->ownership_list, &ownership->name_link);
                ownership->flags = flags;
                r = NAME_E_OWNER_NEW;
        } else if ((flags & DBUS_NAME_FLAG_REPLACE_EXISTING) &&
                   (primary->flags & DBUS_NAME_FLAG_ALLOW_REPLACEMENT)) {
                /* we replace the primary owner */
                change->name = name_ref(name);
                change->old_owner = primary->owner;
                change->new_owner = ownership->owner;

                if (primary->flags & DBUS_NAME_FLAG_DO_NOT_QUEUE)
                        /* the previous primary owner is dropped */
                        name_ownership_free(primary);

                if (c_list_is_linked(&ownership->name_link)) {
                        c_list_unlink(&ownership->name_link);
                        r = NAME_E_OWNER_UPDATED;
                } else {
                        r = NAME_E_OWNER_NEW;
                }
                c_list_link_front(&name->ownership_list, &ownership->name_link);
                ownership->flags = flags;
        } else if (!(flags & DBUS_NAME_FLAG_DO_NOT_QUEUE)) {
                /* we are appended to the queue */
                if (!c_list_is_linked(&ownership->name_link)) {
                        c_list_link_tail(&name->ownership_list, &ownership->name_link);
                        r = NAME_E_IN_QUEUE_NEW;
                } else {
                        r = NAME_E_IN_QUEUE_UPDATED;
                }
                ownership->flags = flags;
        } else {
                /* we are dropped */
                name_ownership_free(ownership);
                r = NAME_E_EXISTS;
        }

        return r;
}

void name_ownership_release(NameOwnership *ownership, NameChange *change) {
        assert(!change->name);
        assert(!change->old_owner);
        assert(!change->new_owner);

        if (name_ownership_is_primary(ownership)) {
                NameOwner *new_owner;

                if (c_list_last(&ownership->name->ownership_list) != &ownership->name_link) {
                        NameOwnership *next = c_list_entry(ownership->name_link.next, NameOwnership, name_link);
                        new_owner = next->owner;
                } else {
                        new_owner = NULL;
                }

                change->name = name_ref(ownership->name);
                change->old_owner = ownership->owner;
                change->new_owner = new_owner;
        }

        name_ownership_free(ownership);
}

/* new name entry linked into the registry */
static int name_new(Name **namep, NameRegistry *registry, const char *name_str, CRBNode *parent, CRBNode **slot) {
        Name *name;
        size_t n_name;

        n_name = strlen(name_str) + 1;

        name = malloc(sizeof(*name) + n_name);
        if (!name)
                return error_origin(-ENOMEM);

        name->n_refs = C_REF_INIT;
        name->registry = registry;
        name->activation = NULL;
        match_registry_init(&name->matches);
        c_rbtree_add(&registry->name_tree, parent, slot, &name->registry_node);
        name->ownership_list = (CList)C_LIST_INIT(name->ownership_list);
        memcpy((char*)name->name, name_str, n_name);

        *namep = name;
        return 0;
}

void name_free(_Atomic unsigned long *n_refs, void *userpointer) {
        Name *name = c_container_of(n_refs, Name, n_refs);

        assert(c_list_is_empty(&name->ownership_list));
        assert(!name->activation);

        c_rbtree_remove(&name->registry->name_tree, &name->registry_node);

        match_registry_deinit(&name->matches);

        free(name);
}

bool name_is_owned(Name *name) {
        return !c_list_is_empty(&name->ownership_list);
}

static int name_compare(CRBTree *tree, void *k, CRBNode *rb) {
        Name *name = c_container_of(rb, Name, registry_node);

        return strcmp(k, name->name);
}

int name_get(Name **namep, NameRegistry *registry, const char *name_str) {
        CRBNode **slot, *parent;
        int r;

        slot = c_rbtree_find_slot(&registry->name_tree, name_compare, name_str, &parent);
        if (!slot) {
                *namep = name_ref(c_container_of(parent, Name, registry_node));
        } else {
                r = name_new(namep, registry, name_str, parent, slot);
                if (r)
                        return error_trace(r);
        }

        return 0;
}

void name_registry_init(NameRegistry *registry) {
        *registry = (NameRegistry) {};
}

void name_registry_deinit(NameRegistry *registry) {
        assert(c_rbtree_is_empty(&registry->name_tree));
}

int name_registry_request_name(NameRegistry *registry, NameOwner *owner, const char *name_str, uint32_t flags, NameChange *change) {
        _c_cleanup_(name_unrefp) Name *name = NULL;
        NameOwnership *ownership;
        int r;

        r = name_get(&name, registry, name_str);
        if (r)
                return error_trace(r);

        r = name_ownership_get(&ownership, owner, name);
        if (r)
                return error_trace(r);

        r = name_ownership_update(ownership, flags, change);
        if (r)
                return error_trace(r);

        return 0;
}

Name *name_registry_find_name(NameRegistry *registry, const char *name_str) {
        return c_rbtree_find_entry(&registry->name_tree, name_compare, name_str, Name, registry_node);
}

int name_registry_release_name(NameRegistry *registry, NameOwner *owner, const char *name_str, NameChange *change) {
        Name *name;
        NameOwnership *ownership;

        name = name_registry_find_name(registry, name_str);
        if (!name)
                return NAME_E_NOT_FOUND;

        ownership = c_rbtree_find_entry(&owner->ownership_tree, name_ownership_compare, name, NameOwnership, owner_node);
        if (!ownership)
                return NAME_E_NOT_OWNER;

        name_ownership_release(ownership, change);

        return 0;
}

NameOwner *name_registry_resolve_owner(NameRegistry *registry, const char *name_str) {
        Name *name;
        NameOwnership *ownership;

        name = c_rbtree_find_entry(&registry->name_tree, name_compare, name_str, Name, registry_node);
        if (!name)
                return NULL;

        ownership = c_list_first_entry(&name->ownership_list, NameOwnership, name_link);

        return ownership ? ownership->owner : NULL;
}

void name_owner_init(NameOwner *owner) {
        *owner = (NameOwner){};
}

void name_owner_deinit(NameOwner *owner) {
        assert(c_rbtree_is_empty(&owner->ownership_tree));
}
