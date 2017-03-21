/*
 * User Accounting
 */

#include <c-macro.h>
#include <c-ref.h>
#include <stdlib.h>
#include <sys/types.h>
#include "user.h"

struct UserUsage {
        _Atomic unsigned long n_refs;
        UserEntry *entry;

        unsigned int n_bytes;
        unsigned int n_fds;

        uid_t uid;
        CRBNode rb;
};

struct UserRegistry {
        unsigned int max_bytes;
        unsigned int max_fds;
        unsigned int max_names;
        unsigned int max_peers;

        CRBTree users;
};

static int user_usage_compare(CRBTree *tree, void *k, CRBNode *rb) {
        UserUsage *usage = c_container_of(rb, UserUsage, rb);
        uid_t uid = *(uid_t*)k;

        if (usage->uid > uid)
                return -1;
        if (usage->uid < uid)
                return 1;

        return 0;
}

static void user_usage_link(UserUsage *usage,
                            UserEntry *entry,
                            CRBNode *parent,
                            CRBNode **slot) {
        entry->n_usages ++;
        usage->entry = entry;
        c_rbtree_add(&entry->usages, parent, slot, &usage->rb);
}

static void user_usage_unlink(UserUsage *usage) {
        UserEntry *entry = usage->entry;

        c_rbtree_remove_init(&entry->usages, &usage->rb);
        usage->entry = NULL;
        entry->n_usages --;
}

static int user_usage_new(UserUsage **usagep, uid_t uid) {
        UserUsage *usage;

        usage = malloc(sizeof(*usage));
        if (!usage)
                return -ENOMEM;

        usage->n_refs = C_REF_INIT;
        usage->uid = uid;
        usage->n_bytes = 0;
        usage->n_fds = 0;
        usage->entry = NULL;

        *usagep = usage;
        return 0;
}

static void user_usage_free(_Atomic unsigned long *n_refs, void *userdata) {
        UserUsage *usage = c_container_of(n_refs, UserUsage, n_refs);

        assert(usage->n_bytes == 0);
        assert(usage->n_fds == 0);

        user_usage_unlink(usage);

        free(usage);
}

static UserUsage *user_usage_ref(UserUsage *usage) {
        if (usage)
                c_ref_inc(&usage->n_refs);

        return usage;
}

static UserUsage *user_usage_unref(UserUsage *usage) {
        if (usage)
                c_ref_dec(&usage->n_refs, user_usage_free, NULL);

        return NULL;
}

C_DEFINE_CLEANUP(UserUsage *, user_usage_unref);

static int user_usage_ref_by_actor(UserEntry *entry,
                                   UserUsage **usagep,
                                   UserEntry *actor) {
        UserUsage *usage;
        CRBNode **slot, *parent;
        int r;

        slot = c_rbtree_find_slot(&entry->usages,
                                  user_usage_compare,
                                  &actor->uid,
                                  &parent);
        if (slot) {
                r = user_usage_new(&usage, actor->uid);
                if (r < 0)
                        return r;

                user_usage_link(usage, entry, parent, slot);
        } else {
                usage = c_container_of(parent, UserUsage, rb);
                user_usage_ref(usage);
        }

        *usagep = usage;
        return 0;
}

/**
 * user_charge_init() - initialize charge object
 * @charge:     charge object to initialize
 *
 * This initializes a new charge object.
 */
void user_charge_init(UserCharge *charge) {
        charge->usage = NULL;
        charge->n_bytes = 0;
        charge->n_fds = 0;
}

/**
 * user_charge_deinit() - destroy charge object
 * @charge:     charge object to destroy
 *
 * This destroys a charge object that was previously initialized via
 * user_charge_init(). The caller must make sure the object is not currently in
 * use before calling this.
 *
 * This function is a no-op and only does safety checks on the charge object.
 */
void user_charge_deinit(UserCharge *charge) {
        assert(!charge->usage);
        assert(charge->n_bytes == 0);
        assert(charge->n_fds == 0);
}

static int user_charge_check(unsigned int remaining,
                             unsigned int users,
                             unsigned int share,
                             unsigned int charge) {
        if (remaining - charge < (share + charge) * users)
                return -EDQUOT;

        return 0;
}

/**
 * user_charge_apply() - apply a charge
 * @charge:     charge object used to record the charge
 * @entry:      user entry to charge on
 * @actor:      user entry charged on behalf of
 * @n_bytes:    number of bytes to charge
 * @n_fds:      number of fds to charge
 *
 * Charge @entry @n_bytes and @n_fds on behalf of @actor. Record the charge in
 * @charge so it can later be undone.
 *
 * @charge must be initialized and not currently be in use.
 *
 * @actor is at most allowed to consume an n'th of @entry's resources that have
 * not been consumed by any other user, where n is one more than the total
 * number of actors currently pinning any of @entry's resources. If this quota
 * is exceeded the charge fails to apply and this is a no-op.
 *
 * Return: 0 on success, or a negative error code on failure.
 */
int user_charge_apply(UserCharge *charge,
                      UserEntry *entry,
                      UserEntry *actor,
                      unsigned int n_bytes,
                      unsigned int n_fds) {
        _c_cleanup_(user_usage_unrefp) UserUsage *usage = NULL;
        int r;

        assert(!charge->usage);

        r = user_usage_ref_by_actor(entry, &usage, actor);
        if (r < 0)
                return r;

        r = user_charge_check(entry->n_bytes,
                              entry->n_usages,
                              usage->n_bytes,
                              n_bytes);
        if (r < 0)
                return r;

        r = user_charge_check(entry->n_fds,
                              entry->n_usages,
                              usage->n_fds,
                              n_fds);
        if (r < 0)
                return r;

        entry->n_bytes -= n_bytes;
        entry->n_fds -= n_fds;
        usage->n_bytes += n_bytes;
        usage->n_fds += n_fds;

        charge->n_bytes = n_bytes;
        charge->n_fds = n_fds;
        charge->usage = usage;
        usage = NULL;

        return 0;
}

/**
 * user_charge_release() - undo a charge
 * @charge:     object to operate on
 *
 * This reverses the effect of user_charge_apply(), and releases the pinned
 * resources, allowing the charge object to be reused.
 */
void user_charge_release(UserCharge *charge) {
        UserUsage *usage = charge->usage;
        UserEntry *entry = usage->entry;

        entry->n_bytes += charge->n_bytes;
        entry->n_fds += charge->n_fds;
        usage->n_bytes -= charge->n_bytes;
        usage->n_fds -= charge->n_fds;
        charge->n_bytes = 0;
        charge->n_fds = 0;

        charge->usage = user_usage_unref(charge->usage);
}

static void user_entry_link(UserEntry *entry,
                            UserRegistry *registry,
                            CRBNode *parent,
                            CRBNode **slot) {
        c_rbtree_add(&registry->users, parent, slot, &entry->rb);
        entry->registry = registry;
}

static void user_entry_unlink(UserEntry *entry) {
        UserRegistry *registry = entry->registry;

        c_rbtree_remove_init(&registry->users, &entry->rb);
        entry->registry = NULL;
}

static int user_entry_new(UserEntry **entryp,
                          uid_t uid,
                          unsigned int max_bytes,
                          unsigned int max_fds,
                          unsigned int max_names,
                          unsigned int max_peers) {
        UserEntry *entry;

        entry = malloc(sizeof(*entry));
        if (!entry)
                return -ENOMEM;

        entry->n_refs = C_REF_INIT;
        entry->uid = uid;
        entry->max_bytes = max_bytes;
        entry->max_fds = max_fds;
        entry->max_names = max_names;
        entry->max_peers = max_peers;
        entry->n_bytes = entry->max_bytes;
        entry->n_fds = entry->max_fds;
        entry->n_names = entry->max_names;
        entry->n_peers = entry->max_peers;
        entry->usages = (CRBTree){};
        entry->n_usages = 0;
        entry->registry = NULL;

        *entryp = entry;

        return 0;
}

/**
 * user_entry_free() - destroy a user entry
 * @n_refs:             the reference count
 * @userdata:           unused userdata
 *
 * This is the callback called when the last reference to the user entry has
 * been released. It verifies that the object is infact unused, unregisteres it
 * from the user registry and frees the resources.
 */
void user_entry_free(_Atomic unsigned long *n_refs, void *userdata) {
        UserEntry *entry = c_container_of(n_refs, UserEntry, n_refs);

        assert(!entry->usages.root);
        assert(entry->n_usages == 0);

        assert(entry->n_bytes == entry->max_bytes);
        assert(entry->n_fds == entry->max_fds);
        assert(entry->n_names == entry->max_names);
        assert(entry->n_peers == entry->max_peers);

        user_entry_unlink(entry);

        free(entry);
}

static int user_entry_compare(CRBTree *tree, void *k, CRBNode *rb) {
        UserEntry *entry = c_container_of(rb, UserEntry, rb);
        uid_t uid = *(uid_t*)k;

        if (entry->uid > uid)
                return -1;
        if (entry->uid < uid)
                return 1;

        return 0;
}

/**
 * user_entry_ref_by_uid() - lookup entry in registry
 * @registry:           registry to query
 * @entryp:             pointer to entry
 * @uid:                uid of entry to lookup
 *
 * This looks up a user entry with UID @uid in @registry, if it exists, and
 * acquires a new refernce to it. If the entry does not exist in the registry,
 * it is created and added to the registry before being returned.
 *
 * Return: 0 on success, or a negative error code on failure.
 */
int user_entry_ref_by_uid(UserRegistry *registry,
                          UserEntry **entryp,
                          uid_t uid) {
        UserEntry *entry;
        CRBNode **slot, *parent;
        int r;

        slot = c_rbtree_find_slot(&registry->users,
                                  user_entry_compare,
                                  &uid,
                                  &parent);
        if (slot) {
                r = user_entry_new(&entry, uid,
                                   registry->max_bytes,
                                   registry->max_fds,
                                   registry->max_names,
                                   registry->max_peers);
                if (r < 0)
                        return r;

                user_entry_link(entry, registry, parent, slot);
        } else {
                entry = c_container_of(parent, UserEntry, rb);
                user_entry_ref(entry);
        }

        *entryp = entry;

        return 0;
}

/**
 * user_registry_new() - allocate a new user registry
 * @registryp:          pointer to the new registry
 * @max_bytes:          max bytes allocated to each user
 * @max_fds:            max fds allocated to each user
 * @max_names:          max names owned by each user
 * @max_peers:          max peers owned by each user
 *
 * Allocate a new user registry. New user entries can be instantiated from the
 * registry, in which case they are assigned the maximum number of resources as
 * given in @max_bytes, @max_fds, @max_names and @max_peers.
 *
 * Return: 0 on success, or a negative error code on failure.
 */
int user_registry_new(UserRegistry **registryp,
                      unsigned int max_bytes,
                      unsigned int max_fds,
                      unsigned int max_names,
                      unsigned int max_peers) {
        UserRegistry *registry;

        registry = malloc(sizeof(*registry));
        if (!registry)
                return -ENOMEM;

        registry->max_bytes = max_bytes;
        registry->max_fds = max_fds;
        registry->max_names = max_names;
        registry->max_peers = max_peers;
        registry->users = (CRBTree) {};

        *registryp = registry;

        return 0;
}

/**
 * user_registry_free() - destroy user registry
 * @registry:           user registry to operate on, or NULL
 *
 * This destroys the user registry, previously created via user_registry_new().
 * All user elements instantiated from the registry must have been destroyed
 * before the registry is freed.
 *
 * If @registry is NULL, this is a no-op.
 */
void user_registry_free(UserRegistry *registry) {
        if (!registry)
                return;

        assert(!registry->users.root);

        free(registry);
}
