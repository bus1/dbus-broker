#pragma once

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

#include <c-macro.h>
#include <c-rbtree.h>
#include <c-ref.h>
#include <stdlib.h>
#include <sys/types.h>

typedef struct UserCharge UserCharge;
typedef struct UserUsage UserUsage;
typedef struct User User;
typedef struct UserRegistry UserRegistry;

enum {
        _USER_E_SUCCESS,

        USER_E_QUOTA,
};

struct UserCharge {
        UserUsage *usage;

        unsigned int n_bytes;
        unsigned int n_fds;
};

struct User {
        _Atomic unsigned long n_refs;
        UserRegistry *registry;

        uid_t uid;
        CRBNode registry_node;

        unsigned int n_bytes;
        unsigned int n_fds;
        unsigned int n_names;
        unsigned int n_peers;
        unsigned int n_matches;
        unsigned int max_bytes;
        unsigned int max_fds;
        unsigned int max_names;
        unsigned int max_peers;
        unsigned int max_matches;

        CRBTree usage_tree;
        unsigned int n_usages;
};

struct UserRegistry {
        unsigned int max_bytes;
        unsigned int max_fds;
        unsigned int max_peers;
        unsigned int max_names;
        unsigned int max_matches;

        CRBTree user_tree;
};

/* charge */

void user_charge_init(UserCharge *charge);
void user_charge_deinit(UserCharge *charge);

/* user */

void user_free(_Atomic unsigned long *n_refs, void *userdata);

int user_charge(User *user,
                UserCharge *charge,
                User *actor,
                unsigned int n_bytes,
                unsigned int n_fds);

/* registry */

#define USER_REGISTRY_INIT(_bytes, _fds, _peers, _names, _matches) {    \
                .max_bytes = _bytes,                                    \
                .max_fds = _fds,                                        \
                .max_peers = _peers,                                    \
                .max_names = _names,                                    \
                .max_matches = _matches,                                \
        }

void user_registry_init(UserRegistry *registry,
                        unsigned int max_bytes,
                        unsigned int max_fds,
                        unsigned int max_peers,
                        unsigned int max_names,
                        unsigned int max_matches);
void user_registry_deinit(UserRegistry *registry);

int user_registry_ref_user(UserRegistry *registry, User **userp, uid_t uid);

/**
 * user_ref() - acquire reference
 * @user:              user object to acquire, or NULL
 *
 * Acquire an additional reference to a user-object. The caller must already
 * own a reference.
 *
 * If NULL is passed, this is a no-op.
 *
 * Return: @user is returned.
 */
static inline User *user_ref(User *user) {
        if (user)
                c_ref_inc(&user->n_refs);
        return user;
}

/**
 * user_unref() - release reference
 * @user:              user object to release, or NULL
 *
 * Release a reference to a user-object.
 *
 * If NULL is passed, this is a no-op.
 *
 * Return: NULL is returned.
 */
static inline User *user_unref(User *user) {
        if (user)
                c_ref_dec(&user->n_refs, user_free, NULL);
        return NULL;
}

C_DEFINE_CLEANUP(User *, user_unref);
