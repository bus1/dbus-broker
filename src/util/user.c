/*
 * User Accounting
 *
 * Different users can communicate via the broker, and some resources are
 * shared between multiple users. The User object represents the UID of a
 * user, like "struct user_struct" does in the kernel. It is used to account
 * global resources, apply limits, and calculate quotas if different UIDs
 * communicate with each other.
 *
 * All dynamic resources have global per-user limits, which cannot be exceeded
 * by a user. They prevent a single user from exhausting local resources. Each
 * peer that is created is always owned by the user that initialized it. All
 * resources allocated on that peer are accounted on that pinned user.
 *
 * Since the broker allows communication across UID boundaries, any such
 * transmission of resources must be properly accounted. The broker employs
 * dynamic quotas to fairly distribute available resources. Those quotas make
 * sure that available resources of a peer cannot be exhausted by remote UIDs,
 * but are fairly divided among all communicating peers. The share granted to
 * each remote UID is between 1/n and 1/n^2 of the total amount of resources
 * available to the local UID, where n is the number of UIDs consuming a share
 * of the local UID's resources at the time of accounting.
 */

#include <c-stdaux.h>
#include <stdlib.h>
#include <sys/types.h>
#include "util/error.h"
#include "util/log.h"
#include "util/ref.h"
#include "util/user.h"

static void user_usage_link(UserUsage *usage, CRBNode *parent, CRBNode **slot) {
        ++usage->user->n_usages;
        c_rbtree_add(&usage->user->usage_tree, parent, slot, &usage->user_node);
}

static void user_usage_unlink(UserUsage *usage) {
        c_rbnode_unlink(&usage->user_node);
        --usage->user->n_usages;
}

static int user_usage_new(UserUsage **usagep, User *user, uid_t uid) {
        UserUsage *usage;

        usage = calloc(1, sizeof(*usage) + user->registry->n_slots * sizeof(*usage->slots));
        if (!usage)
                return error_origin(-ENOMEM);

        usage->n_refs = REF_INIT;
        usage->user = user_ref(user);
        usage->uid = uid;
        usage->user_node = (CRBNode)C_RBNODE_INIT(usage->user_node);

        *usagep = usage;
        return 0;
}

static void user_usage_free(_Atomic unsigned long *n_refs, void *userdata) {
        UserUsage *usage = c_container_of(n_refs, UserUsage, n_refs);
        size_t i;

        for (i = 0; i < usage->user->registry->n_slots; ++i)
                c_assert(!usage->slots[i]);

        user_usage_unlink(usage);
        user_unref(usage->user);
        free(usage);
}

static UserUsage *user_usage_ref(UserUsage *usage) {
        if (usage)
                ref_inc(&usage->n_refs);
        return usage;
}

static UserUsage *user_usage_unref(UserUsage *usage) {
        if (usage)
                ref_dec(&usage->n_refs, user_usage_free, NULL);
        return NULL;
}

C_DEFINE_CLEANUP(UserUsage *, user_usage_unref);

static int user_usage_compare(CRBTree *tree, void *k, CRBNode *rb) {
        UserUsage *usage = c_container_of(rb, UserUsage, user_node);
        uid_t uid = *(uid_t*)k;

        if (uid < usage->uid)
                return -1;
        if (uid > usage->uid)
                return 1;

        return 0;
}

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
                charge->usage->user->slots[charge->slot].n += charge->charge;
                charge->usage->slots[charge->slot] -= charge->charge;

                charge->usage = user_usage_unref(charge->usage);
                charge->slot = 0;
                charge->charge = 0;
        } else {
                c_assert(!charge->charge);
        }
}

static int user_charge_check(unsigned int remaining,
                             unsigned int users,
                             unsigned int share,
                             unsigned int charge) {
        unsigned int limit;

        /*
         * For a given allocation scheme `A(users)`, a single allocation is
         * allowed to request anything less than, or equal to:
         *
         *               remaining + share
         *     charge <= ~~~~~~~~~~~~~~~~~ - share
         *                   A(users)
         *
         * We want to avoid a division, so instead we modify the equation to
         * end up as:
         *
         *     A(users) * (charge + share) - share <= remaining
         *
         * Note that currently we use an allocator with polynomial guarantees:
         *
         *     A(users) = users + 1
         */

        if (!__builtin_add_overflow(share, charge, &limit) &&
            !__builtin_mul_overflow(limit, users + 1, &limit) &&
            !__builtin_sub_overflow(limit, share, &limit) &&
            limit <= remaining)
                return 0;

        return USER_E_QUOTA;
}

static void user_link(User *user, CRBNode *parent, CRBNode **slot) {
        c_rbtree_add(&user->registry->user_tree, parent, slot, &user->registry_node);
}

static void user_unlink(User *user) {
        c_rbnode_unlink(&user->registry_node);
}

static int user_new(User **userp, UserRegistry *registry, uid_t uid) {
        User *user;
        size_t i;

        user = calloc(1, sizeof(*user) + registry->n_slots * sizeof(*user->slots));
        if (!user)
                return error_origin(-ENOMEM);

        user->n_refs = REF_INIT;
        user->registry = registry;
        user->uid = uid;
        user->registry_node = (CRBNode)C_RBNODE_INIT(user->registry_node);
        user->usage_tree = (CRBTree)C_RBTREE_INIT;

        for (i = 0; i < registry->n_slots; ++i) {
                user->slots[i].max = registry->maxima[i];
                user->slots[i].n = user->slots[i].max;
        }

        *userp = user;
        return 0;
}

void user_free(_Atomic unsigned long *n_refs, void *userdata) {
        User *user = c_container_of(n_refs, User, n_refs);
        size_t i;

        c_assert(c_rbtree_is_empty(&user->usage_tree));
        c_assert(user->n_usages == 0);

        for (i = 0; i < user->registry->n_slots; ++i)
                c_assert(user->slots[i].n == user->slots[i].max);

        user_unlink(user);
        free(user);
}

static int user_ref_usage(User *user, UserUsage **usagep, User *actor) {
        UserUsage *usage;
        CRBNode **slot, *parent;
        int r;

        slot = c_rbtree_find_slot(&user->usage_tree, user_usage_compare, &actor->uid, &parent);
        if (slot) {
                r = user_usage_new(&usage, user, actor->uid);
                if (r)
                        return r;

                user_usage_link(usage, parent, slot);
        } else {
                usage = c_container_of(parent, UserUsage, user_node);
                user_usage_ref(usage);
        }

        *usagep = usage;
        return 0;
}

static int user_charge_commit_log(Log *log, User *user, UserCharge *charge, User *actor, size_t slot, unsigned int amount) {
        int r;

        if (!log)
                return 0;

        if (charge->usage->logged)
                return 0;

        c_assert(slot < user->registry->n_slots);

        log_appendf(log, "DBUS_BROKER_USER_CHARGE_USER=%u\n", user->uid);
        log_appendf(log, "DBUS_BROKER_USER_CHARGE_ACTOR=%u\n", actor->uid);
        log_appendf(log, "DBUS_BROKER_USER_CHARGE_AMOUNT=%u\n", amount);
        log_appendf(log, "DBUS_BROKER_USER_CHARGE_N_ACTORS=%u\n", user->n_usages);
        log_appendf(log, "DBUS_BROKER_USER_CHARGE_SLOT=%s\n", user_slot_to_string(slot));
        log_appendf(log, "DBUS_BROKER_USER_CHARGE_REMAINING=%u\n", user->slots[slot].n);
        log_appendf(log, "DBUS_BROKER_USER_CHARGE_CONSUMED=%u\n", charge->usage->slots[slot]);

        r = log_commitf(log, "UID %u exceeded its '%s' quota on UID %u.", actor->uid, user_slot_to_string(slot), user->uid);
        if (r)
                return error_fold(r);

        charge->usage->logged = true;

        return 0;
}

/**
 * user_charge() - charge a user object
 * @user:       user object to charge
 * @charge:     charge object used to record the charge
 * @actor:      user object charged on behalf of, or NULL
 * @slot:       slot to charge
 * @amount:     charge amount
 *
 * Charge @amount units on slot @slot on behalf of @actor. Record the charge in
 * @charge so it can later be undone.
 *
 * @charge must be initialized and either be unused or already charged on the
 * @user + @actor combination.
 *
 * @actor is at most allowed to consume an n'th of @user's resources that have
 * not been consumed by any other user, where n is one more than the total
 * number of actors currently pinning any of @user's resources. If this quota
 * is exceeded the charge fails to apply and nothing is charged. The first time
 * a certain quota fails for a certain @user / @actor a message is written to
 * the log.
 *
 * If @actor is NULL it is taken to be @user itself.
 *
 * If @user is NULL, this is a no-op and @charge stays untouched.
 *
 * Return: 0 on success, error code on failure.
 */
int user_charge(User *user, UserCharge *charge, User *actor, size_t slot, unsigned int amount) {
        _c_cleanup_(user_usage_unrefp) UserUsage *usage = NULL;
        unsigned int *user_slot, *usage_slot;
        int r;

        /* no charge, no work */
        if (!amount)
                return 0;

        /* excluded from accounting */
        if (!user)
                return 0;

        /* charge to itself */
        if (!actor)
                actor = user;

        if (charge->usage) {
                c_assert(user == charge->usage->user);
                c_assert(actor->uid == charge->usage->uid);
                c_assert(slot == charge->slot);
                usage = user_usage_ref(charge->usage);
        } else {
                r = user_ref_usage(user, &usage, actor);
                if (r)
                        return error_trace(r);
        }

        c_assert(slot < user->registry->n_slots);
        user_slot = &user->slots[slot].n;
        usage_slot = &usage->slots[slot];

        if (user == actor) {
                /* never apply quotas on self-charge */
                if (amount > *user_slot)
                        goto quota;
        } else {
                r = user_charge_check(*user_slot, user->n_usages, *usage_slot, amount);
                if (r) {
                        if (r == USER_E_QUOTA)
                                goto quota;

                        return error_trace(r);
                }
        }

        *user_slot -= amount;
        *usage_slot += amount;
        charge->charge += amount;

        if (!charge->usage) {
                charge->slot = slot;
                charge->usage = usage;
                usage = NULL;
        }

        return 0;
quota:
        if (!charge->usage) {
                charge->slot = slot;
                charge->usage = usage;
                usage = NULL;
        }

        r = user_charge_commit_log(user->registry->log, user, charge, actor, slot, amount);
        if (r)
                return error_trace(r);

        return USER_E_QUOTA;
}

static int user_compare(CRBTree *tree, void *k, CRBNode *rb) {
        User *user = c_container_of(rb, User, registry_node);
        uid_t uid = *(uid_t*)k;

        if (uid < user->uid)
                return -1;
        if (uid > user->uid)
                return 1;

        return 0;
}

/**
 * user_registry_init() - initialize user registry
 * @registry:           user registry to operate on
 * @log:                destination of any log messages
 * @n_slots:            number of accounting slots
 * @maxima:             maxima for each slot
 *
 * Initialize a user registry. @n_slots defines the number of distinct
 * accounting slots that will be available on all users on that registry.
 *
 * Return: 0 on success, negative error code on failure.
 */
int user_registry_init(UserRegistry *registry,
                       Log *log,
                       size_t n_slots,
                       const unsigned int *maxima) {
        static_assert(sizeof(*maxima) == sizeof(*registry->maxima),
                      "Type mismatch for maxima");

        *registry = (UserRegistry)USER_REGISTRY_NULL;

        registry->maxima = calloc(n_slots, sizeof(*registry->maxima));
        if (!registry->maxima)
                return error_origin(-ENOMEM);

        registry->log = log;
        registry->n_slots = n_slots;
        c_memcpy(registry->maxima, maxima, n_slots * sizeof(*registry->maxima));

        return 0;
}

/**
 * user_registry_deinit() - destroy user registry
 * @registry:           user registry to operate on
 *
 * This destroys a user registry, previously initialized via
 * user_registry_init(). All user elements instantiated from the registry must
 * have been destroyed before the registry is deinitialized.
 */
void user_registry_deinit(UserRegistry *registry) {
        c_assert(c_rbtree_is_empty(&registry->user_tree));

        free(registry->maxima);
        *registry = (UserRegistry)USER_REGISTRY_NULL;
}

/**
 * user_registry_ref_user() - search user in registry
 * @registry:           registry to query
 * @userp:              output argument for user object
 * @uid:                uid of user to search for
 *
 * This searches for a user object with UID @uid in @registry, takes a
 * reference and returns it in @userp.
 *
 * Return: 0 on success, error code on failure.
 */
int user_registry_ref_user(UserRegistry *registry, User **userp, uid_t uid) {
        User *user;
        CRBNode **slot, *parent;
        int r;

        slot = c_rbtree_find_slot(&registry->user_tree, user_compare, &uid, &parent);
        if (slot) {
                r = user_new(&user, registry, uid);
                if (r)
                        return error_trace(r);

                user_link(user, parent, slot);
        } else {
                user = c_container_of(parent, User, registry_node);
                user_ref(user);
        }

        *userp = user;
        return 0;
}
