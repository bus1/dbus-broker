/*
 * BusSELinuxRegistry Helpers
 */

#include <c-macro.h>
#include <c-rbtree.h>
#include <c-ref.h>
#include <selinux/selinux.h>
#include <selinux/avc.h>
#include <stdlib.h>
#include "util/error.h"
#include "util/selinux.h"

struct BusSELinuxRegistry {
        _Atomic unsigned long n_refs;
        security_id_t fallback_sid;
        CRBTree names;
};

struct BusSELinuxName {
        security_id_t sid;
        CRBNode rb;
        char name[];
};

typedef struct BusSELinuxName BusSELinuxName;

#define BUS_SELINUX_SID_FROM_ID(id)     ((security_id_t) (id))
#define BUS_SELINUX_SID_TO_ID(sid)      ((BusSELinuxID*) (sid))

#define BUS_SELINUX_CLASS_DBUS          (1UL)

#define BUS_SELINUX_PERMISSION_OWN      (1UL)
#define BUS_SELINUX_PERMISSION_SEND     (2UL)

static struct security_class_mapping dbus_class_map[] = {
  { "dbus", { "acquire_svc", "send_msg", NULL } },
  { NULL }
};

/** bus_selinux_is_enabled() - checks if SELinux is currently enabled
 *
 * Returns: true if SELinux is enabled, false otherwise.
 */
bool bus_selinux_is_enabled(void) {
        return is_selinux_enabled();
}

/**
 * bus_selinux_policy_root() - the root directory where the current SELinux policy can be found
 *
 * The current SELinux policy can be found in a different directory depending on the
 * current configuration.
 *
 * Return: a path to the directory, or NULL if it is not known.
 */
const char *bus_selinux_policy_root(void) {
        return selinux_policy_root();
}

/**
 * bus_selinux_id_init() - initialize the SELinux ID
 * @idp:                pointer to ID
 * @seclabel:           seclabel to initialize from
 *
 * If SELinux is enabled, @seclabel is assumed to be a valid SELinux
 * security context and is used to initialized the ID. Otherwise,
 * the seclabel nothing is assumed about the seclabel, it is ignored
 * and instead the ID is initialized to the invalid SELinux ID.
 *
 * Return: 0 on success, or a negative error code on failure.
 */
int bus_selinux_id_init(BusSELinuxID **idp, const char *seclabel) {
        security_id_t sid;
        int r;

        /*
         * If SELinux is not enabled, we better not assume anything about the
         * security label and not try to convert it to a SID. A SELinux
         * security context is a null-terminated string, but a security label
         * from another LSM may not be.
         */
        if (!is_selinux_enabled()) {
                *idp = BUS_SELINUX_SID_TO_ID(SECSID_WILD);
                return 0;
        }

        r = avc_context_to_sid(seclabel, &sid);
        if (r < 0)
                return error_origin(-errno);

        *idp = BUS_SELINUX_SID_TO_ID(sid);

        return 0;
}

static BusSELinuxName *bus_selinux_name_free(BusSELinuxName *name) {
        if (!name)
                return NULL;

        assert(!c_rbnode_is_linked(&name->rb));

        free(name);

        return NULL;
}

C_DEFINE_CLEANUP(BusSELinuxName *, bus_selinux_name_free);

static int bus_selinux_name_new(const char *name, const char *context, CRBTree *tree, CRBNode *parent, CRBNode **slot) {
        _c_cleanup_(bus_selinux_name_freep) BusSELinuxName *selinux_name = NULL;
        size_t n_name = strlen(name) + 1;
        int r;

        selinux_name = malloc(sizeof(*selinux_name) + n_name);
        if (!selinux_name)
                return error_origin(-ENOMEM);
        selinux_name->rb = (CRBNode)C_RBNODE_INIT(selinux_name->rb);
        selinux_name->sid = SECSID_WILD;
        memcpy(selinux_name->name, name, n_name);

        r = avc_context_to_sid(context, &selinux_name->sid);
        if (r < 0)
                return error_origin(-errno);

        c_rbtree_add(tree, parent, slot, &selinux_name->rb);
        selinux_name = NULL;

        return 0;
}

/**
 * bus_selinux_registry_new() - create a new SELinux registry
 * @registryp:          pointer to the new registry
 * @fallback_id:        fallback ID for queries against this registry
 *
 * A registry contains a set of names associated with security contexts, and
 * a fallback ID that should be used as the ID of the broker itself and for
 * names without anything explicitly associated.
 *
 * Return: 0 on success, or a negative error code on failure.
 */
int bus_selinux_registry_new(BusSELinuxRegistry **registryp, BusSELinuxID *fallback_id) {
        _c_cleanup_(bus_selinux_registry_unrefp) BusSELinuxRegistry *registry = NULL;

        registry = malloc(sizeof(*registry));
        if (!registry)
                return error_origin(-ENOMEM);

        registry->n_refs = C_REF_INIT;
        registry->fallback_sid = BUS_SELINUX_SID_FROM_ID(fallback_id);
        registry->names = (CRBTree)C_RBTREE_INIT;

        *registryp = registry;
        registry = NULL;
        return 0;
}

static void bus_selinux_registry_free(_Atomic unsigned long *n_refs, void *userdata) {
        BusSELinuxRegistry *registry = c_container_of(n_refs, BusSELinuxRegistry, n_refs);
        BusSELinuxName *name, *name_safe;

        c_rbtree_for_each_entry_unlink(name, name_safe, &registry->names, rb)
                bus_selinux_name_free(name);

        free(registry);
}

BusSELinuxRegistry *bus_selinux_registry_ref(BusSELinuxRegistry *registry) {
        if (registry)
                c_ref_inc(&registry->n_refs);

        return registry;
}

BusSELinuxRegistry *bus_selinux_registry_unref(BusSELinuxRegistry *registry) {
        if (registry)
                c_ref_dec(&registry->n_refs, bus_selinux_registry_free, NULL);

        return NULL;
}

static int name_compare(CRBTree *t, void *k, CRBNode *rb) {
        const char *name = (const char *)k;
        BusSELinuxName *selinux_name = c_container_of(rb, BusSELinuxName, rb);

        return strcmp(name, selinux_name->name);
}

/**
 * bus_selinux_registry_add_name() - add a name and its associated security context to the registry
 * @registry:           the registry to operate on
 * @name:               the add to associate with a security context
 * @context:            a valid SELinux security context
 *
 * Associates the given name with the given SELinux security context in the registry.
 *
 * If the name already exists in the registry, it is silently updated with the new
 * security context.
 *
 * Return: 0 on success, or a negative error code on failure.
 */
int bus_selinux_registry_add_name(BusSELinuxRegistry *registry, const char *name, const char *context) {
        CRBNode *parent, **slot;
        int r;

        slot = c_rbtree_find_slot(&registry->names, name_compare, name, &parent);
        if (slot) {
                r = bus_selinux_name_new(name, context, &registry->names, parent, slot);
                if (r)
                        return error_trace(r);
        } else {
                BusSELinuxName *selinux_name;

                selinux_name = c_container_of(parent, BusSELinuxName, rb);

                /* The name already exists, simply silently override the SID. */
                r = avc_context_to_sid(context, &selinux_name->sid);
                if (r < 0)
                        return error_origin(-errno);
        }

        return 0;
}

/**
 * bus_selinux_check_own() - check if the given transaction is allowed
 * @registry:           SELinux registry to operate on
 * @owner_id:           ID of the owner
 * @name:               name to be owned
 *
 * Check if the given owner ID is allowed to own the given name.
 *
 * The query is performed with the IDs associated with names in the
 * SELinux registry. If no ID is associated with a given name the
 * registry-wide fallback ID is used instead.
 *
 * The IDs are pinned when peers connect, and as such could in principle
 * become invalid in case a new policy is loaded that does not know the
 * old labels. In this case we treat this as if the ownership request was
 * denied.
 *
 * Return: 0 if the ownership is allowed, SELINUX_E_DENIED if it is not,
 *         or a negative error code on failure.
 */
int bus_selinux_check_own(BusSELinuxRegistry *registry,
                          BusSELinuxID *owner_id,
                          const char *name) {
        BusSELinuxName *selinux_name;
        security_id_t name_sid;
        int r;

        if (!is_selinux_enabled())
                return 0;

        selinux_name = c_rbtree_find_entry(&registry->names, name_compare, name, BusSELinuxName, rb);
        if (selinux_name)
                name_sid = selinux_name->sid;
        else
                name_sid = registry->fallback_sid;

        r = avc_has_perm_noaudit(BUS_SELINUX_SID_FROM_ID(owner_id),
                                 name_sid,
                                 BUS_SELINUX_CLASS_DBUS,
                                 BUS_SELINUX_PERMISSION_OWN,
                                 NULL, NULL);
        if (r < 0) {
                /*
                 * Treat unknown contexts (possibly due to policy reload)
                 * as access denied.
                 */
                if (errno == EACCES || errno == EINVAL)
                        return SELINUX_E_DENIED;

                return error_origin(-errno);
        }

        return 0;
}

/**
 * bus_selinux_check_send() - check if the given transaction is allowed
 * @registry:           SELinux registry to operate on
 * @sender_id:          ID of the sender
 * @receiver_id:        ID of the receiver, or NULL
 *
 * Check if the given sender ID is allowed to send a message to the given
 * receiver ID. If the receiver ID is given as NULL, the per-registry
 * fallback ID is used instead.
 *
 * The IDs are pinned when peers connect, and as such could in principle
 * become invalid in case a new policy is loaded that does not know the
 * old labels. In this case we treat this as if the transaction was
 * denied.
 *
 * Return: 0 if the transaction is allowed, SELINUX_E_DENIED if it is not,
 *         or a negative error code on failure.
 */
int bus_selinux_check_send(BusSELinuxRegistry *registry,
                           BusSELinuxID *sender_id,
                           BusSELinuxID *receiver_id) {
        security_id_t receiver_sid;
        int r;

        if (!is_selinux_enabled())
                return 0;

        receiver_sid = receiver_id ? BUS_SELINUX_SID_FROM_ID(receiver_id) : registry->fallback_sid;

        r = avc_has_perm_noaudit(BUS_SELINUX_SID_FROM_ID(sender_id),
                                 receiver_sid,
                                 BUS_SELINUX_CLASS_DBUS,
                                 BUS_SELINUX_PERMISSION_SEND,
                                 NULL, NULL);
        if (r < 0) {
                /*
                 * Treat unknown contexts (possibly due to policy reload)
                 * as access denied.
                 */
                if (errno == EACCES || errno == EINVAL)
                        return SELINUX_E_DENIED;

                return error_origin(-errno);
        }

        return 0;
}

/**
 * bus_selinux_init_global() - initialize the global SELinux context
 *
 * Initialize the global SELinux context. This must be called before any
 * other SELinux function.
 *
 * Return: 0 on success, or a negative error code on failure.
 */
int bus_selinux_init_global(void) {
        int r;

        if (!is_selinux_enabled())
                return 0;

        r = selinux_set_mapping(dbus_class_map);
        if (r < 0)
                return error_origin(-errno);

        r = avc_open(NULL, 0);
        if (r)
                return error_origin(-errno);

        /* XXX: set logging callbacks? */

        return 0;
}

/**
 * bus_selinux_deinit_global() - deinitialize the global SELinux context
 *
 * Cleans up the resources initialized by bus_selinux_init_global(). This
 * must be called exactly once, after which no more SELinux functions can
 * be called.
 */
void bus_selinux_deinit_global(void) {
        if (!is_selinux_enabled())
                return;

        avc_destroy();
}
