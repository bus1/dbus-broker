/*
 * BusSELinuxRegistry Helpers
 */

#include <c-rbtree.h>
#include <c-stdaux.h>
#include <selinux/selinux.h>
#include <selinux/avc.h>
#include <stdlib.h>
#include "util/audit.h"
#include "util/error.h"
#include "util/ref.h"
#include "util/selinux.h"

struct BusSELinuxRegistry {
        _Atomic unsigned long n_refs;
        const char *fallback_context;
        CRBTree names;
};

struct BusSELinuxName {
        char *context;
        CRBNode rb;
        char name[];
};

typedef struct BusSELinuxName BusSELinuxName;

static bool bus_selinux_avc_open;
static bool bus_selinux_status_open;

/**
 * bus_selinux_is_enabled() - checks if SELinux is currently enabled
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

static BusSELinuxName *bus_selinux_name_free(BusSELinuxName *name) {
        if (!name)
                return NULL;

        c_assert(!c_rbnode_is_linked(&name->rb));

        free(name->context);
        free(name);

        return NULL;
}

C_DEFINE_CLEANUP(BusSELinuxName *, bus_selinux_name_free);

static int bus_selinux_name_new(const char *name, const char *context, CRBTree *tree, CRBNode *parent, CRBNode **slot) {
        _c_cleanup_(bus_selinux_name_freep) BusSELinuxName *selinux_name = NULL;
        size_t n_name = strlen(name) + 1;

        selinux_name = malloc(sizeof(*selinux_name) + n_name);
        if (!selinux_name)
                return error_origin(-ENOMEM);
        selinux_name->rb = (CRBNode)C_RBNODE_INIT(selinux_name->rb);
        selinux_name->context = NULL;
        c_memcpy(selinux_name->name, name, n_name);

        selinux_name->context = strdup(context);
        if (!selinux_name->context)
                return error_origin(-ENOMEM);

        c_rbtree_add(tree, parent, slot, &selinux_name->rb);
        selinux_name = NULL;

        return 0;
}

/**
 * bus_selinux_registry_new() - create a new SELinux registry
 * @registryp:          pointer to the new registry
 * @fallback_context:   fallback security context for queries against this registry
 *
 * A registry contains a set of names associated with security contexts, and
 * a fallback security context that should be used as the context of the broker
 * itself and for names without anything explicitly associated.
 *
 * Return: 0 on success, or a negative error code on failure.
 */
int bus_selinux_registry_new(BusSELinuxRegistry **registryp, const char *fallback_context) {
        _c_cleanup_(bus_selinux_registry_unrefp) BusSELinuxRegistry *registry = NULL;
        size_t n_fallback_context = strlen(fallback_context) + 1;

        registry = malloc(sizeof(*registry) + n_fallback_context);
        if (!registry)
                return error_origin(-ENOMEM);

        registry->n_refs = REF_INIT;
        registry->fallback_context = (const char *)(registry + 1);
        registry->names = (CRBTree)C_RBTREE_INIT;
        c_memcpy((char *)registry->fallback_context, fallback_context, n_fallback_context);

        *registryp = registry;
        registry = NULL;
        return 0;
}

static void bus_selinux_registry_free(_Atomic unsigned long *n_refs, void *userdata) {
        BusSELinuxRegistry *registry = c_container_of(n_refs, BusSELinuxRegistry, n_refs);
        BusSELinuxName *name, *name_safe;

        c_rbtree_for_each_entry_safe_postorder_unlink(name, name_safe, &registry->names, rb)
                bus_selinux_name_free(name);

        free(registry);
}

BusSELinuxRegistry *bus_selinux_registry_ref(BusSELinuxRegistry *registry) {
        if (registry)
                ref_inc(&registry->n_refs);

        return registry;
}

BusSELinuxRegistry *bus_selinux_registry_unref(BusSELinuxRegistry *registry) {
        if (registry)
                ref_dec(&registry->n_refs, bus_selinux_registry_free, NULL);

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
                char *context_new;

                selinux_name = c_container_of(parent, BusSELinuxName, rb);

                /* The name already exists, simply silently override the context. */
                context_new = strdup(context);
                if (!context_new)
                        return error_origin(-ENOMEM);

                free(selinux_name->context);
                selinux_name->context = context_new;
        }

        return 0;
}

/**
 * bus_selinux_check_own() - check if the given transaction is allowed
 * @registry:           SELinux registry to operate on
 * @owner_context:      security context of the owner
 * @name:               name to be owned
 *
 * Check if the given owner context is allowed to own the given name.
 *
 * The query is performed with the contexts associated with names in the
 * SELinux registry. If no context is associated with a given name the
 * registry-wide fallback context is used instead.
 *
 * The contexts are pinned when peers connect, and as such could in principle
 * become invalid in case a new policy is loaded that does not know the
 * old labels. In this case we treat this as if the ownership request was
 * denied.
 *
 * Return: 0 if the ownership is allowed, SELINUX_E_DENIED if it is not,
 *         or a negative error code on failure.
 */
int bus_selinux_check_own(BusSELinuxRegistry *registry,
                          const char *owner_context,
                          const char *name) {
        BusSELinuxName *selinux_name;
        const char *name_context;
        int r;

        if (!is_selinux_enabled())
                return 0;

        selinux_name = c_rbtree_find_entry(&registry->names, name_compare, name, BusSELinuxName, rb);
        if (selinux_name)
                name_context = selinux_name->context;
        else
                name_context = registry->fallback_context;

        r = selinux_check_access(owner_context,
                                 name_context,
                                 "dbus",
                                 "acquire_svc",
                                 NULL);
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
 * @sender_context:     security context of the sender
 * @receiver_context:   security context of the receiver, or NULL
 *
 * Check if the given sender context is allowed to send a message to the
 * given receiver context. If the receiver context is given as NULL, the
 * per-registry fallback context is used instead.
 *
 * The contexts are pinned when peers connect, and as such could in principle
 * become invalid in case a new policy is loaded that does not know the
 * old labels. In this case we treat this as if the transaction was
 * denied.
 *
 * Return: 0 if the transaction is allowed, SELINUX_E_DENIED if it is not,
 *         or a negative error code on failure.
 */
int bus_selinux_check_send(BusSELinuxRegistry *registry,
                           const char *sender_context,
                           const char *receiver_context) {
        int r;

        if (!is_selinux_enabled())
                return 0;

        receiver_context = receiver_context ?: registry->fallback_context;

        r = selinux_check_access(sender_context,
                                 receiver_context,
                                 "dbus",
                                 "send_msg",
                                 NULL);
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

static int bus_selinux_log(int type, const char *fmt, ...) {
        _c_cleanup_(c_freep) char *message = NULL;
        va_list ap;
        int r, audit_type;

        va_start(ap, fmt);
        r = vasprintf(&message, fmt, ap);
        va_end(ap);
        if (r < 0)
                return r;

        switch(type) {
        case SELINUX_AVC:
                audit_type = UTIL_AUDIT_TYPE_AVC;
                break;
        case SELINUX_POLICYLOAD:
                audit_type = UTIL_AUDIT_TYPE_POLICYLOAD;
                break;
        case SELINUX_SETENFORCE:
                audit_type = UTIL_AUDIT_TYPE_MAC_STATUS;
                break;
        default:
                /* not an auditable message. */
                audit_type = UTIL_AUDIT_TYPE_NOAUDIT;
                break;
        }

        /* XXX: we don't have access to any context, so can't find
         * the right UID to use, follow dbus-daemon(1) and use our
         * own. */
        r = util_audit_log(audit_type, message, getuid());
        if (r)
                return error_fold(r);

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

        if (!bus_selinux_avc_open) {
                r = avc_open(NULL, 0);
                if (r)
                        return error_origin(-errno);

                bus_selinux_avc_open = true;
        }

        if (!bus_selinux_status_open) {
                r = selinux_status_open(0);
                if (r == 0) {
                        /*
                         * The status page was successfully opened and can now
                         * be used for faster selinux status-checks.
                         */
                        bus_selinux_status_open = true;
                } else if (r > 0) {
                        /*
                         * >0 indicates success but with the netlink-fallback.
                         * We didn't request the netlink-fallback, so close the
                         * status-page again and treat it as unavailable.
                         */
                        selinux_status_close();
                } else {
                        /*
                         * If the status page could not be opened, treat it as
                         * unavailable and use the slower fallback functions.
                         */
                }
        }

        selinux_set_callback(SELINUX_CB_LOG, (union selinux_callback)bus_selinux_log);

        /* XXX: set audit callback to get more metadata in the audit log? */

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

        if (bus_selinux_status_open) {
                selinux_status_close();
                bus_selinux_status_open = false;
        }

        if (bus_selinux_avc_open) {
                avc_destroy();
                bus_selinux_avc_open = false;
        }
}
