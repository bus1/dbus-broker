#pragma once

/*
 * User Accounting
 */

#include <c-rbtree.h>
#include <c-stdaux.h>
#include <stdlib.h>
#include <sys/types.h>
#include "util/ref.h"

typedef struct Log Log;
typedef struct UserCharge UserCharge;
typedef struct UserUsage UserUsage;
typedef struct User User;
typedef struct UserRegistry UserRegistry;

/* XXX: move this to some global broker header file */
enum {
        USER_SLOT_BYTES,
        USER_SLOT_FDS,
        USER_SLOT_MATCHES,
        USER_SLOT_OBJECTS,
        _USER_SLOT_N,
};

static inline const char *user_slot_to_string(size_t slot) {
        switch (slot) {
        case USER_SLOT_BYTES:
                return "bytes";
        case USER_SLOT_FDS:
                return "FDs";
        case USER_SLOT_MATCHES:
                return "matches";
        case USER_SLOT_OBJECTS:
                return "objects";
        default:
                c_assert(0);
                abort();
        }
}

enum {
        _USER_E_SUCCESS,

        USER_E_QUOTA,
};

/* usage */

struct UserUsage {
        _Atomic unsigned long n_refs;
        User *user;
        uid_t uid;
        CRBNode user_node;

        bool logged : 1;

        unsigned int slots[];
};

/* charge */

struct UserCharge {
        UserUsage *usage;
        size_t slot;
        unsigned int charge;
};

#define USER_CHARGE_INIT {}

void user_charge_init(UserCharge *charge);
void user_charge_deinit(UserCharge *charge);

/* user */

struct User {
        _Atomic unsigned long n_refs;
        UserRegistry *registry;
        uid_t uid;
        CRBNode registry_node;

        CRBTree usage_tree;
        unsigned int n_usages;

        struct {
                unsigned int n;
                unsigned int max;
        } slots[];
};

void user_free(_Atomic unsigned long *n_refs, void *userdata);
int user_charge(User *user, UserCharge *charge, User *actor, size_t slot, unsigned int amount);

/* registry */

struct UserRegistry {
        Log *log;
        CRBTree user_tree;
        size_t n_slots;
        unsigned int *maxima;
};

#define USER_REGISTRY_NULL {                                                    \
                .user_tree = C_RBTREE_INIT,                                     \
        }

int user_registry_init(UserRegistry *registry, Log *log, size_t n_slots, const unsigned int *maxima);
void user_registry_deinit(UserRegistry *registry);
int user_registry_ref_user(UserRegistry *registry, User **userp, uid_t uid);

/* inline helpers */

static inline User *user_ref(User *user) {
        if (user)
                ref_inc(&user->n_refs);
        return user;
}

static inline User *user_unref(User *user) {
        if (user)
                ref_dec(&user->n_refs, user_free, NULL);
        return NULL;
}

C_DEFINE_CLEANUP(User *, user_unref);
