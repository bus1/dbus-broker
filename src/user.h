#pragma once

/*
 * D-Bus User Accounting
 *
 * Different users can communicate via the dbus broker, and many resources are
 * shared between multiple users. The UserEntry object represents the UID of a
 * user, like "struct user_struct" does in the kernel. It is used to account
 * global resources, apply limits, and calculate quotas if different UIDs
 * communicate with each other.
 *
 * All dynamic resources have global per-user limits, which cannot be exceeded
 * by a user. They prevent a single user from exhausting local resources. Each
 * peer that is created is always owned by the user that initialized it. All
 * resources allocated on that peer are accounted on that pinned user.
 * Additionally to global resources, there are local limits per peer, that can
 * be controlled by each peer individually (e.g., specifying a maximum pool
 * size). Those local limits allow a user to distribute the globally available
 * resources across its peer instances.
 *
 * Since the dbus broker allows communication across UID boundaries, any such
 * transmission of resources must be properly accounted. The dbus broker employs
 * dynamic quotas to fairly distribute available resources. Those quotas make
 * sure that available resources of a peer cannot be exhausted by remote UIDs,
 * but are fairly divided among all communicating peers.
 */

#include <c-macro.h>
#include <c-rbtree.h>
#include <c-ref.h>
#include <stdlib.h>
#include <sys/types.h>

typedef struct UserCharge UserCharge;
typedef struct UserUsage UserUsage;
typedef struct UserEntry UserEntry;
typedef struct UserRegistry UserRegistry;

struct UserCharge {
        UserUsage *usage;
        unsigned int n_bytes;
        unsigned int n_fds;
};

struct UserEntry {
        _Atomic unsigned long n_refs;
        UserRegistry *registry;
        uid_t uid;
        unsigned int n_bytes;
        unsigned int n_fds;
        unsigned int max_bytes;
        unsigned int max_fds;
        CRBTree usages;
        unsigned int n_usages;
        CRBNode rb;
};

/* charges */
void user_charge_init(UserCharge *charge);
void user_charge_deinit(UserCharge *charge);

int user_charge_apply(UserCharge *charge,
                      UserEntry *entry,
                      UserEntry *actor,
                      unsigned int n_bytes,
                      unsigned int n_fds);
void user_charge_release(UserCharge *charge);

/* users */
int user_entry_ref_by_uid(UserRegistry *registry,
                          UserEntry **userp,
                          uid_t uid);
void user_entry_free(_Atomic unsigned long *n_refs, void *userdata);

/* registry */
int user_registry_new(UserRegistry **registryp,
                      unsigned int max_bytes,
                      unsigned int max_fds);
void user_registry_free(UserRegistry *registry);

/**
 * user_entry_ref() - acquire reference
 * @entry:        user entry to acquire, or NULL
 *
 * Acquire an additional reference to a user-object. The caller must already
 * own a reference.
 *
 * If NULL is passed, this is a no-op.
 *
 * Return: @entry is returned.
 */
static inline UserEntry *user_entry_ref(UserEntry *entry) {
        if (entry)
                c_ref_inc(&entry->n_refs);
        return entry;
}

/**
 * user_entry_unref() - release reference
 * @entry:        user entry to release, or NULL
 *
 * Release a reference to a user-object.
 *
 * If NULL is passed, this is a no-op.
 *
 * Return: NULL is returned.
 */
static inline UserEntry *user_entry_unref(UserEntry *entry) {
        if (entry)
                c_ref_dec(&entry->n_refs, user_entry_free, NULL);
        return NULL;
}

C_DEFINE_CLEANUP(UserEntry *, user_entry_unref);
