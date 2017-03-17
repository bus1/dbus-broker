/*
 * User Accounting
 */

#include <c-macro.h>
#include <c-ref.h>
#include <stdlib.h>
#include "user.h"

struct UserUsage {
        _Atomic unsigned long n_refs;
        UserEntry *entry;
        uid_t uid;
        unsigned int n_bytes;
        unsigned int n_fds;
        CRBNode rb;
};

struct UserRegistry {
        unsigned int max_bytes;
        unsigned int max_fds;
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
 * user_charge_init() - XXX
 */
void user_charge_init(UserCharge *charge) {
        *charge = (UserCharge){};
}

/**
 * user_charge_deinit() - XXX
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
 * user_charge_apply() - XXX
 */
int user_charge_apply(UserCharge *charge,
                      UserEntry *entry,
                      UserEntry *actor,
                      unsigned int n_bytes,
                      unsigned int n_fds) {
        _c_cleanup_(user_usage_unrefp) UserUsage *usage = NULL;
        int r;

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
 * user_charge_release() - XXX
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
                          unsigned int max_fds) {
        UserEntry *entry;

        entry = malloc(sizeof(*entry));
        if (!entry)
                return -ENOMEM;

        entry->n_refs = C_REF_INIT;
        entry->uid = uid;
        entry->max_bytes = max_bytes;
        entry->max_fds = max_fds;
        entry->n_bytes = entry->max_bytes;
        entry->n_fds = entry->max_fds;
        entry->usages = (CRBTree){};
        entry->n_usages = 0;
        entry->registry = NULL;

        *entryp = entry;

        return 0;
}

/**
 * user_entry_free() - XXX
 */
void user_entry_free(_Atomic unsigned long *n_refs, void *userdata) {
        UserEntry *entry = c_container_of(n_refs, UserEntry, n_refs);

        assert(!entry->usages.root);
        assert(entry->n_usages == 0);

        assert(entry->n_bytes == entry->max_bytes);
        assert(entry->n_fds == entry->max_fds);

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
 * user_entry_ref_by_uid() - XXX
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
                                   registry->max_fds);
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
 * user_registry_new() - XXX
 */
int user_registry_new(UserRegistry **registryp,
                      unsigned int max_bytes,
                      unsigned int max_fds) {
        UserRegistry *registry;

        registry = malloc(sizeof(*registry));
        if (!registry)
                return -ENOMEM;

        registry->max_bytes = max_bytes;
        registry->max_fds = max_fds;
        registry->users = (CRBTree) {};

        *registryp = registry;

        return 0;
}

/**
 * user_registry_free() - XXX
 */
void user_registry_free(UserRegistry *registry) {
        assert(!registry->users.root);

        free(registry);
}
