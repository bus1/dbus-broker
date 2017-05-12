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
        User *user;

        uid_t uid;
        CRBNode user_node;

        unsigned int n_bytes;
        unsigned int n_fds;
};

static int user_usage_compare(CRBTree *tree, void *k, CRBNode *rb) {
        UserUsage *usage = c_container_of(rb, UserUsage, user_node);
        uid_t uid = *(uid_t*)k;

        if (uid < usage->uid)
                return -1;
        if (uid > usage->uid)
                return 1;

        return 0;
}

static void user_usage_link(UserUsage *usage, CRBNode *parent, CRBNode **slot) {
        ++usage->user->n_usages;
        c_rbtree_add(&usage->user->usage_tree, parent, slot, &usage->user_node);
}

static void user_usage_unlink(UserUsage *usage) {
        c_rbtree_remove_init(&usage->user->usage_tree, &usage->user_node);
        --usage->user->n_usages;
}

static int user_usage_new(UserUsage **usagep, User *user, uid_t uid) {
        UserUsage *usage;

        usage = calloc(1, sizeof(*usage));
        if (!usage)
                return error_origin(-ENOMEM);

        usage->n_refs = C_REF_INIT;
        usage->user = user;
        usage->uid = uid;
        usage->user_node = (CRBNode)C_RBNODE_INIT(usage->user_node);

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
                charge->usage->user->n_bytes += charge->n_bytes;
                charge->usage->user->n_fds += charge->n_fds;
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

static void user_link(User *user,
                      CRBNode *parent,
                      CRBNode **slot) {
        c_rbtree_add(&user->registry->user_tree, parent, slot, &user->registry_node);
}

static void user_unlink(User *user) {
        c_rbtree_remove_init(&user->registry->user_tree, &user->registry_node);
}

static int user_new(User **userp,
                    UserRegistry *registry,
                    uid_t uid,
                    unsigned int max_bytes,
                    unsigned int max_fds,
                    unsigned int max_peers,
                    unsigned int max_names,
                    unsigned int max_matches) {
        User *user;

        user = calloc(1, sizeof(*user));
        if (!user)
                return error_origin(-ENOMEM);

        user->n_refs = C_REF_INIT;
        user->registry = registry;
        user->uid = uid;
        user->registry_node = (CRBNode)C_RBNODE_INIT(user->registry_node);
        user->max_bytes = max_bytes;
        user->max_fds = max_fds;
        user->max_peers = max_peers;
        user->max_names = max_names;
        user->max_matches = max_matches;
        user->n_bytes = user->max_bytes;
        user->n_fds = user->max_fds;
        user->n_peers = user->max_peers;
        user->n_names = user->max_names;
        user->n_matches = user->max_matches;

        *userp = user;
        return 0;
}

void user_free(_Atomic unsigned long *n_refs, void *userdata) {
        User *user = c_container_of(n_refs, User, n_refs);

        assert(!user->usage_tree.root);
        assert(user->n_usages == 0);

        assert(user->n_bytes == user->max_bytes);
        assert(user->n_fds == user->max_fds);
        assert(user->n_peers == user->max_peers);
        assert(user->n_names == user->max_names);
        assert(user->n_matches == user->max_matches);

        user_unlink(user);
        free(user);
}

static int user_ref_usage(User *user,
                          UserUsage **usagep,
                          User *actor) {
        UserUsage *usage;
        CRBNode **slot, *parent;
        int r;

        slot = c_rbtree_find_slot(&user->usage_tree,
                                  user_usage_compare,
                                  &actor->uid,
                                  &parent);
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

/**
 * user_charge() - charge a user object
 * @user:      user object to charge
 * @charge:     charge object used to record the charge
 * @actor:      user object charged on behalf of
 * @n_bytes:    number of bytes to charge
 * @n_fds:      number of fds to charge
 *
 * Charge @user @n_bytes and @n_fds on behalf of @actor. Record the charge in
 * @charge so it can later be undone.
 *
 * @charge must be initialized and not currently be in use.
 *
 * @actor is at most allowed to consume an n'th of @user's resources that have
 * not been consumed by any other user, where n is one more than the total
 * number of actors currently pinning any of @user's resources. If this quota
 * is exceeded the charge fails to apply and this is a no-op.
 *
 * Return: 0 on success, error code on failure.
 */
int user_charge(User *user,
                UserCharge *charge,
                User *actor,
                unsigned int n_bytes,
                unsigned int n_fds) {
        _c_cleanup_(user_usage_unrefp) UserUsage *usage = NULL;
        int r;

        assert(!charge->usage);

        r = user_ref_usage(user, &usage, actor);
        if (r)
                return error_trace(r);

        r = user_charge_check(user->n_bytes,
                              user->n_usages,
                              usage->n_bytes,
                              n_bytes);
        if (r)
                return error_trace(r);

        r = user_charge_check(user->n_fds,
                              user->n_usages,
                              usage->n_fds,
                              n_fds);
        if (r)
                return error_trace(r);

        user->n_bytes -= n_bytes;
        user->n_fds -= n_fds;
        usage->n_bytes += n_bytes;
        usage->n_fds += n_fds;

        charge->n_bytes = n_bytes;
        charge->n_fds = n_fds;
        charge->usage = usage;
        usage = NULL;

        return 0;
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
        assert(!registry->user_tree.root);

        *registry = (UserRegistry){};
}

/**
 * user_registry_ref_user() - search user in registry
 * @registry:           registry to query
 * @userp:             output argument for user object
 * @uid:                uid of user to search for
 *
 * This searches for a user object with UID @uid in @registry, takes a reference
 * and returns it in @userp.
 *
 * Return: 0 on success, error code on failure.
 */
int user_registry_ref_user(UserRegistry *registry, User **userp, uid_t uid) {
        User *user;
        CRBNode **slot, *parent;
        int r;

        slot = c_rbtree_find_slot(&registry->user_tree, user_compare, &uid, &parent);
        if (slot) {
                r = user_new(&user,
                             registry,
                             uid,
                             registry->max_bytes,
                             registry->max_fds,
                             registry->max_peers,
                             registry->max_names,
                             registry->max_matches);
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
