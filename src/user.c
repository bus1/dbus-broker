/*
 * User Accounting
 */

#include <c-macro.h>
#include <c-ref.h>
#include <stdlib.h>
#include <sys/types.h>
#include "user.h"
#include "util/error.h"

struct UserUsage {
        _Atomic unsigned long n_refs;
        UserEntry *entry;

        uid_t uid;
        CRBNode rb;

        unsigned int n_bytes;
        unsigned int n_fds;
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

static void user_usage_link(UserUsage *usage, CRBNode *parent, CRBNode **slot) {
        ++usage->entry->n_usages;
        c_rbtree_add(&usage->entry->usages, parent, slot, &usage->rb);
}

static void user_usage_unlink(UserUsage *usage) {
        c_rbtree_remove_init(&usage->entry->usages, &usage->rb);
        --usage->entry->n_usages;
}

static int user_usage_new(UserUsage **usagep, UserEntry *entry, uid_t uid) {
        UserUsage *usage;

        usage = calloc(1, sizeof(*usage));
        if (!usage)
                return error_origin(-ENOMEM);

        usage->n_refs = C_REF_INIT;
        usage->entry = entry;
        usage->uid = uid;
        usage->rb = (CRBNode)C_RBNODE_INIT(usage->rb);

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

/**
 * user_charge_init() - initialize charge object
 * @charge:     charge object to initialize
 *
 * This initializes a new charge object.
 */
void user_charge_init(UserCharge *charge) {
        *charge = (UserCharge){};
}

/**
 * user_charge_deinit() - destroy charge object
 * @charge:     charge object to destroy
 *
 * This destroys a charge object that was previously initialized via
 * user_charge_init(). If the object was never charged, this is a no-op.
 * Otherwise, the charge is released and the object is re-initialized.
 */
void user_charge_deinit(UserCharge *charge) {
        if (charge->usage) {
                charge->usage->entry->n_bytes += charge->n_bytes;
                charge->usage->entry->n_fds += charge->n_fds;
                charge->usage->n_bytes -= charge->n_bytes;
                charge->usage->n_fds -= charge->n_fds;

                charge->usage = user_usage_unref(charge->usage);
                charge->n_bytes = 0;
                charge->n_fds = 0;
        } else {
                assert(charge->n_bytes == 0);
                assert(charge->n_fds == 0);
        }
}

static int user_charge_check(unsigned int remaining,
                             unsigned int users,
                             unsigned int share,
                             unsigned int charge) {
        if (remaining - charge < (share + charge) * users)
                return USER_E_QUOTA;

        return 0;
}

static void user_entry_link(UserEntry *entry,
                            CRBNode *parent,
                            CRBNode **slot) {
        c_rbtree_add(&entry->registry->users, parent, slot, &entry->rb);
}

static void user_entry_unlink(UserEntry *entry) {
        c_rbtree_remove_init(&entry->registry->users, &entry->rb);
}

static int user_entry_new(UserEntry **entryp,
                          UserRegistry *registry,
                          uid_t uid,
                          unsigned int max_bytes,
                          unsigned int max_fds,
                          unsigned int max_peers,
                          unsigned int max_names,
                          unsigned int max_matches) {
        UserEntry *entry;

        entry = calloc(1, sizeof(*entry));
        if (!entry)
                return error_origin(-ENOMEM);

        entry->n_refs = C_REF_INIT;
        entry->registry = registry;
        entry->uid = uid;
        entry->rb = (CRBNode)C_RBNODE_INIT(entry->rb);
        entry->max_bytes = max_bytes;
        entry->max_fds = max_fds;
        entry->max_peers = max_peers;
        entry->max_names = max_names;
        entry->max_matches = max_matches;
        entry->n_bytes = entry->max_bytes;
        entry->n_fds = entry->max_fds;
        entry->n_peers = entry->max_peers;
        entry->n_names = entry->max_names;
        entry->n_matches = entry->max_matches;

        *entryp = entry;
        return 0;
}

void user_entry_free(_Atomic unsigned long *n_refs, void *userdata) {
        UserEntry *entry = c_container_of(n_refs, UserEntry, n_refs);

        assert(!entry->usages.root);
        assert(entry->n_usages == 0);

        assert(entry->n_bytes == entry->max_bytes);
        assert(entry->n_fds == entry->max_fds);
        assert(entry->n_peers == entry->max_peers);
        assert(entry->n_names == entry->max_names);
        assert(entry->n_matches == entry->max_matches);

        user_entry_unlink(entry);
        free(entry);
}

static int user_entry_ref_usage(UserEntry *entry,
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
                r = user_usage_new(&usage, entry, actor->uid);
                if (r)
                        return r;

                user_usage_link(usage, parent, slot);
        } else {
                usage = c_container_of(parent, UserUsage, rb);
                user_usage_ref(usage);
        }

        *usagep = usage;
        return 0;
}

/**
 * user_entry_charge() - charge a user entry
 * @entry:      user entry to charge
 * @charge:     charge object used to record the charge
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
 * Return: 0 on success, error code on failure.
 */
int user_entry_charge(UserEntry *entry,
                      UserCharge *charge,
                      UserEntry *actor,
                      unsigned int n_bytes,
                      unsigned int n_fds) {
        _c_cleanup_(user_usage_unrefp) UserUsage *usage = NULL;
        int r;

        assert(!charge->usage);

        r = user_entry_ref_usage(entry, &usage, actor);
        if (r)
                return error_trace(r);

        r = user_charge_check(entry->n_bytes,
                              entry->n_usages,
                              usage->n_bytes,
                              n_bytes);
        if (r)
                return error_trace(r);

        r = user_charge_check(entry->n_fds,
                              entry->n_usages,
                              usage->n_fds,
                              n_fds);
        if (r)
                return error_trace(r);

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
 * user_registry_init() - initialize a user registry
 * @registry:           the registry to operate on
 * @max_bytes:          max bytes allocated to each user
 * @max_fds:            max fds allocated to each user
 * @max_names:          max names owned by each user
 * @max_peers:          max peers owned by each user
 *
 * Initialized a passed-in user registry. New user entries can be instantiated
 * from the registry, in which case they are assigned the maximum number of
 * resources as given in @max_bytes, @max_fds, @max_names and @max_peers.
 */
void user_registry_init(UserRegistry *registry,
                        unsigned int max_bytes,
                        unsigned int max_fds,
                        unsigned int max_peers,
                        unsigned int max_names,
                        unsigned int max_matches) {
        *registry = (UserRegistry)USER_REGISTRY_INIT(max_bytes, max_fds, max_peers, max_names, max_matches);
}

/**
 * user_registry_deinit() - destroy user registry
 * @registry:           user registry to operate on, or NULL
 *
 * This destroys the user registry, previously initialized via user_registry_init().
 * All user elements instantiated from the registry must have been destroyed
 * before the registry is deinitialized.
 */
void user_registry_deinit(UserRegistry *registry) {
        assert(!registry->users.root);

        *registry = (UserRegistry){};
}

/**
 * user_registry_ref_entry() - search entry in registry
 * @registry:           registry to query
 * @entryp:             output argument for user entry
 * @uid:                uid of entry to search for
 *
 * This searches for a user entry with UID @uid in @registry, takes a reference
 * and returns it in @entryp.
 *
 * Return: 0 on success, error code on failure.
 */
int user_registry_ref_entry(UserRegistry *registry, UserEntry **entryp, uid_t uid) {
        UserEntry *entry;
        CRBNode **slot, *parent;
        int r;

        slot = c_rbtree_find_slot(&registry->users, user_entry_compare, &uid, &parent);
        if (slot) {
                r = user_entry_new(&entry,
                                   registry,
                                   uid,
                                   registry->max_bytes,
                                   registry->max_fds,
                                   registry->max_peers,
                                   registry->max_names,
                                   registry->max_matches);
                if (r)
                        return error_trace(r);

                user_entry_link(entry, parent, slot);
        } else {
                entry = c_container_of(parent, UserEntry, rb);
                user_entry_ref(entry);
        }

        *entryp = entry;
        return 0;
}
