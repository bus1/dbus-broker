/*
 * Name Registry
 */

#include <c-list.h>
#include <c-rbtree.h>
#include <c-stdaux.h>
#include <stdlib.h>
#include "bus/activation.h"
#include "bus/name.h"
#include "dbus/protocol.h"
#include "dbus/socket.h"
#include "util/error.h"
#include "util/misc.h"
#include "util/user.h"

/**
 * name_change_init() - initialize notification
 * @change:             object to operate on
 *
 * Initialize a name-change notification object. All fields are cleared and set
 * to their default values.
 */
void name_change_init(NameChange *change) {
        *change = (NameChange)NAME_CHANGE_INIT;
}

/**
 * name_change_deinit() - deinitialize notification
 * @change:             object to operate on
 *
 * Clear a notification object and drop all references. The object is reset to
 * its default state, as if name_change_init() was called afterwards.
 */
void name_change_deinit(NameChange *change) {
        change->name = name_unref(change->name);
        *change = (NameChange)NAME_CHANGE_INIT;
}

static int name_ownership_compare(CRBTree *tree, void *k, CRBNode *rb) {
        NameOwnership *ownership = c_container_of(rb, NameOwnership, owner_node);

        if ((Name *)k < ownership->name)
                return -1;
        if ((Name *)k > ownership->name)
                return 1;

        return 0;
}

static void name_ownership_link(NameOwnership *ownership, CRBNode *parent, CRBNode **slot) {
        c_assert(!c_rbnode_is_linked(&ownership->owner_node));

        c_rbtree_add(&ownership->owner->ownership_tree, parent, slot, &ownership->owner_node);
}

static NameOwnership *name_ownership_free(NameOwnership *ownership) {
        if (!ownership)
                return NULL;

        c_assert(!c_list_is_linked(&ownership->name_link));

        user_charge_deinit(&ownership->charge);
        c_rbnode_unlink(&ownership->owner_node);
        name_unref(ownership->name);
        free(ownership);

        return NULL;
}

C_DEFINE_CLEANUP(NameOwnership *, name_ownership_free);

static int name_ownership_new(NameOwnership **ownershipp, NameOwner *owner, User *user, Name *name) {
        _c_cleanup_(name_ownership_freep) NameOwnership *ownership = NULL;
        int r;

        ownership = calloc(1, sizeof(*ownership));
        if (!ownership)
                return error_origin(-ENOMEM);

        *ownership = (NameOwnership)NAME_OWNERSHIP_NULL(*ownership);
        ownership->owner = owner;
        ownership->name = name_ref(name);

        r = user_charge(user, &ownership->charge, NULL, USER_SLOT_OBJECTS, 1);
        if (r)
                return (r == USER_E_QUOTA) ? NAME_E_QUOTA : error_fold(r);

        *ownershipp = ownership;
        ownership = NULL;
        return 0;
}

/**
 * name_ownership_is_primary() - check primary state
 * @ownership:          object to operate on
 *
 * This checks whether the given ownership is the primary one.
 *
 * Return: True if @ownership is primary, false otherwise.
 */
bool name_ownership_is_primary(NameOwnership *ownership) {
        return ownership == name_primary(ownership->name);
}

/**
 * name_ownership_release() - release name ownership
 * @ownership:          object to operate on
 * @change:             notification object
 *
 * This releases and destroys the name-ownership object @ownership. This is
 * meant as replacement for name_ownership_free(). Releasing name ownership
 * might require the caller to trigger notifications. Hence, rather than calling
 * name_ownership_free(), you must call its wrapper name_ownership_release(),
 * which then additionally returns required information to you.
 */
void name_ownership_release(NameOwnership *ownership, NameChange *change) {
        NameOwnership *primary;
        Name *name = ownership->name;

        c_assert(!change->name);
        c_assert(!change->old_owner);
        c_assert(!change->new_owner);

        primary = name_primary(name);
        c_list_unlink(&ownership->name_link);

        if (ownership == primary) {
                --ownership->owner->n_owner_primaries;
                --name->registry->n_primaries;

                primary = name_primary(name);

                change->name = name_ref(name);
                change->old_owner = ownership->owner;
                change->new_owner = primary ? primary->owner : NULL;

                if (primary) {
                        // skip `n_primaries_peak` as `n_primaries` did not change
                        ++name->registry->n_primaries;
                        ++primary->owner->n_owner_primaries;
                        util_peak_update(&name->registry->n_owner_primaries_peak, primary->owner->n_owner_primaries);
                }
        }

        name_ownership_free(ownership);
}

static int name_ownership_update(NameOwnership *ownership, uint32_t flags, NameChange *change) {
        Name *name = ownership->name;
        NameOwnership *primary;
        int r;

        c_assert(!change->name);
        c_assert(!change->old_owner);
        c_assert(!change->new_owner);

        primary = name_primary(name);
        ownership->flags = flags;

        if (!primary) {
                /* there is no primary owner */
                change->name = name_ref(name);
                change->old_owner = NULL;
                change->new_owner = ownership->owner;

                /* @owner cannot already be linked */
                c_assert(!c_list_is_linked(&ownership->name_link));

                c_list_link_front(&name->ownership_list, &ownership->name_link);

                ++name->registry->n_primaries;
                ++ownership->owner->n_owner_primaries;
                util_peak_update(&name->registry->n_primaries_peak, name->registry->n_primaries);
                util_peak_update(&name->registry->n_owner_primaries_peak, ownership->owner->n_owner_primaries);

                r = 0;
        } else if (primary == ownership) {
                /* we are already the primary owner */
                r = NAME_E_ALREADY_OWNER;
        } else if ((ownership->flags & DBUS_NAME_FLAG_REPLACE_EXISTING) &&
                   (primary->flags & DBUS_NAME_FLAG_ALLOW_REPLACEMENT)) {
                /* we replace the primary owner */
                change->name = name_ref(name);
                change->old_owner = primary->owner;
                change->new_owner = ownership->owner;

                c_list_unlink(&ownership->name_link);
                c_list_link_front(&name->ownership_list, &ownership->name_link);

                // skip `n_primaries_peak` as `n_primaries` did not change
                --primary->owner->n_owner_primaries;
                ++ownership->owner->n_owner_primaries;
                util_peak_update(&name->registry->n_owner_primaries_peak, ownership->owner->n_owner_primaries);

                /* drop previous primary owner, if queuing is not requested */
                if (primary->flags & DBUS_NAME_FLAG_DO_NOT_QUEUE) {
                        c_list_unlink(&primary->name_link);
                        name_ownership_free(primary);
                }

                r = 0;
        } else if (!(ownership->flags & DBUS_NAME_FLAG_DO_NOT_QUEUE)) {
                /* we are appended to the queue */
                if (!c_list_is_linked(&ownership->name_link))
                        c_list_link_tail(&name->ownership_list, &ownership->name_link);
                r = NAME_E_IN_QUEUE;
        } else {
                /* we are dropped */
                c_list_unlink(&ownership->name_link);
                r = NAME_E_EXISTS;
        }

        return r;
}

static int name_compare(CRBTree *tree, void *k, CRBNode *rb) {
        Name *name = c_container_of(rb, Name, registry_node);

        return strcmp(k, name->name);
}

static void name_link(Name *name, CRBNode *parent, CRBNode **slot) {
        c_assert(!c_rbnode_is_linked(&name->registry_node));

        c_rbtree_add(&name->registry->name_tree, parent, slot, &name->registry_node);
}

static int name_new(Name **namep, NameRegistry *registry, const char *name_str) {
        _c_cleanup_(name_unrefp) Name *name = NULL;
        size_t n_name;

        n_name = strlen(name_str);
        name = malloc(sizeof(*name) + n_name + 1);
        if (!name)
                return error_origin(-ENOMEM);

        *name = (Name)NAME_INIT(*name);
        name->registry = registry;
        c_memcpy(name->name, name_str, n_name + 1);

        *namep = name;
        name = NULL;
        return 0;
}

void name_free(_Atomic unsigned long *n_refs, void *userdata) {
        Name *name = c_container_of(n_refs, Name, n_refs);

        c_assert(c_list_is_empty(&name->ownership_list));
        c_assert(!name->activation);

        match_registry_deinit(&name->name_owner_changed_matches);
        match_registry_deinit(&name->sender_matches);
        c_rbnode_unlink(&name->registry_node);
        free(name);
}

/**
 * name_owner_init() - initialize owner
 * @owner:              object to operate on
 *
 * This initializes a name-owner context.
 */
void name_owner_init(NameOwner *owner) {
        *owner = (NameOwner)NAME_OWNER_INIT;
}

/**
 * name_owner_deinit() - deinitialize owner
 * @owner:              object to operate on
 *
 * This deinitializes a name-owner context. The caller must make sure that the
 * context is unused and does not own any names.
 */
void name_owner_deinit(NameOwner *owner) {
        c_assert(c_rbtree_is_empty(&owner->ownership_tree));
}

/**
 * name_owner_get_stats() - return accounting statistics
 * @owner:              object to operate on
 * @n_objectsp:         return argument for total numbers of accounted objects
 *
 * This calculates the accounting statistics of all names owned by @owner.
 */
void name_owner_get_stats(NameOwner *owner, unsigned int *n_objectsp) {
        NameOwnership *ownership;
        unsigned int n_objects = 0;

        c_rbtree_for_each_entry(ownership, &owner->ownership_tree, owner_node)
                n_objects += ownership->charge.charge;

        *n_objectsp = n_objects;
}

/**
 * name_registry_init() - initialize registry
 * @registry:           object to operate on
 *
 * This initializes a name registry.
 */
void name_registry_init(NameRegistry *registry) {
        *registry = (NameRegistry)NAME_REGISTRY_INIT;
}

/**
 * name_registry_deinit() - deinitialize registry
 * @registry:           object to operate on
 *
 * This deinitializes a name registry. The caller must make sure that the
 * registry is unused and none of its names is pinned, anymore.
 */
void name_registry_deinit(NameRegistry *registry) {
        c_assert(c_rbtree_is_empty(&registry->name_tree));
}

/**
 * name_registry_get_activation_stats_for() - calculate activation-statistics
 *                                            for a peer
 * @registry:           object to operate on
 * @owner_id:           unique ID of the name owner to calculate stats for
 * @n_bytesp:           return argument for total numbers of accounted bytes
 * @n_fdsp:             return argument for total numbers of accounted fds
 *
 * This calculates the statistics for all pending activation messages of a
 * given owner on any names. Note that this information is not indexed, so it
 * is calculated by traversing all names and pending activation messages. You
 * must not use this for anything but debugging.
 */
void name_registry_get_activation_stats_for(NameRegistry *registry,
                                            uint64_t owner_id,
                                            unsigned int *n_bytesp,
                                            unsigned int *n_fdsp) {
        unsigned int n_bytes, n_fds;
        Name *name;

        *n_bytesp = 0;
        *n_fdsp = 0;

        c_rbtree_for_each_entry(name, &registry->name_tree, registry_node) {
                if (name->activation) {
                        activation_get_stats_for(name->activation, owner_id,
                                                 &n_bytes, &n_fds);
                        *n_bytesp += n_bytes;
                        *n_fdsp += n_fds;
                }
        }
}

/**
 * name_registry_ref_name() - reference name object
 * @registry:           registry to operate on
 * @namep:              output argument for name object
 * @name_str:           name to lookup
 *
 * This either creates a new name object with a single reference, or creates a
 * new reference to the name, if it already exists.
 *
 * The pointer to the name is returned in @namep.
 *
 * Return: 0 on success, negative error code on failure.
 */
int name_registry_ref_name(NameRegistry *registry, Name **namep, const char *name_str) {
        CRBNode **slot, *parent;
        int r;

        slot = c_rbtree_find_slot(&registry->name_tree, name_compare, name_str, &parent);
        if (!slot) {
                *namep = name_ref(c_container_of(parent, Name, registry_node));
        } else {
                r = name_new(namep, registry, name_str);
                if (r)
                        return error_trace(r);

                name_link(*namep, parent, slot);
        }

        return 0;
}

/**
 * name_registry_find_name() - find name object
 * @registry:           registry to operate on
 * @name_str:           name to lookup
 *
 * This looks for a name-entry for name @name_str and returns it.
 *
 * Return: Pointer to name-entry, or NULL if not found.
 */
Name *name_registry_find_name(NameRegistry *registry, const char *name_str) {
        return c_rbtree_find_entry(&registry->name_tree, name_compare, name_str, Name, registry_node);
}

/**
 * name_registry_request_name() - request name ownership
 * @registry:           registry to operate on
 * @owner:              owner to act as
 * @user:               user to charge
 * @name_str:           name to request
 * @flags:              flags that affect the operation
 * @change:             notification context
 *
 * This performs a RequestName() operation as defined by the D-Bus
 * specification.
 *
 * Return: 0 on success, NAME_E_QUOTA if @user exceeded its quota,
 *         NAME_E_ALREADY_OWNER if @owner is already the owner of @name_str,
 *         NAME_E_IN_QUEUE of @owner is now queued @name_str, NAME_E_EXISTS if
 *         the name could not be acquired, negative error code on failure.
 */
int name_registry_request_name(NameRegistry *registry,
                               NameOwner *owner,
                               User *user,
                               const char *name_str,
                               uint32_t flags,
                               NameChange *change) {
        _c_cleanup_(name_unrefp) Name *name = NULL;
        NameOwnership *ownership;
        CRBNode **slot, *parent;
        int r;

        r = name_registry_ref_name(registry, &name, name_str);
        if (r)
                return error_trace(r);

        slot = c_rbtree_find_slot(&owner->ownership_tree,
                                  name_ownership_compare,
                                  name,
                                  &parent);
        if (!slot) {
                ownership = c_container_of(parent, NameOwnership, owner_node);
        } else {
                r = name_ownership_new(&ownership, owner, user, name);
                if (r)
                        return error_trace(r);

                name_ownership_link(ownership, parent, slot);
        }

        r = name_ownership_update(ownership, flags, change);
        if (!c_list_is_linked(&ownership->name_link))
                name_ownership_free(ownership);
        return error_trace(r);
}

/**
 * name_registry_release_name() - release name ownership
 * @registry:           registry to operate on
 * @owner:              owner to act as
 * @name_str:           name to release
 * @change:             notification context
 *
 * This performs a ReleaseName() operation as defined by the D-Bus
 * specification.
 *
 * Return: 0 on success, NAME_E_NOT_FOUND if the name does not exist,
 *         NAME_E_NOT_OWNER if @owner does not own the name, negative error
 *         code on failure.
 */
int name_registry_release_name(NameRegistry *registry,
                               NameOwner *owner,
                               const char *name_str,
                               NameChange *change) {
        NameOwnership *ownership;
        Name *name;

        name = name_registry_find_name(registry, name_str);
        if (!name || !name_primary(name))
                return NAME_E_NOT_FOUND;

        ownership = c_rbtree_find_entry(&owner->ownership_tree,
                                        name_ownership_compare,
                                        name,
                                        NameOwnership,
                                        owner_node);
        if (!ownership)
                return NAME_E_NOT_OWNER;

        name_ownership_release(ownership, change);
        return 0;
}

/**
 * name_snapshot_new() - create a snapshot of a name owner
 * @snapshotp:          output argument for snapshot
 * @owner:              owner to take snapshot of
 *
 * The names owned by a name owner are dynamic. However, sometimes we may want
 * to store the names owned at a given point in time. This allows an immutable
 * snapshot to be created of all the names the name owner owns.
 *
 * Return: 0 on success, negative error code on failure.
 */
int name_snapshot_new(NameSnapshot **snapshotp, NameOwner *owner) {
        NameOwnership *ownership;
        NameSnapshot *snapshot;
        size_t n_names = 0;

        c_rbtree_for_each_entry(ownership, &owner->ownership_tree, owner_node)
                ++n_names;

        snapshot = malloc(sizeof(*snapshot) + n_names * sizeof(snapshot->names[0]));
        if (!snapshot)
                return error_origin(-ENOMEM);

        *snapshot = (NameSnapshot)NAME_SNAPSHOT_NULL;

        c_rbtree_for_each_entry(ownership, &owner->ownership_tree, owner_node)
                snapshot->names[snapshot->n_names++] = name_ref(ownership->name);

        c_assert(n_names == snapshot->n_names);

        *snapshotp = snapshot;
        return 0;
}

/**
 * name_snapshot_free() - free a name snapshot
 * @snapshot:           object to free
 *
 * This releases all the resources and frees the snapshot.
 *
 * Return: NULL is returned.
 */
NameSnapshot *name_snapshot_free(NameSnapshot *snapshot) {
        if (!snapshot)
                return NULL;

        for (size_t i = 0; i < snapshot->n_names; ++i)
                name_unref(snapshot->names[i]);

        free(snapshot);

        return NULL;
}
