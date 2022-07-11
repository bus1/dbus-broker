/*
 * Bus AppArmor Helpers
 *
 * Required AppArmor kernel support is still not merged in upstream linux as of
 * July 2022, yet we provide basic AppArmor support based on the downstream
 * Ubuntu patches. This follows closely what dbus-daemon does.
 */

#include <c-rbtree.h>
#include <c-stdaux.h>
#include <libaudit.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/apparmor.h>
#include "bus/name.h"
#include "util/apparmor.h"
#include "util/audit.h"
#include "util/error.h"
#include "util/ref.h"

struct BusAppArmorRegistry {
        _Atomic unsigned long n_refs;
        char *fallback_context;
        char *bustype;
};

/**
 * bus_apparmor_is_enabled() - checks if AppArmor is currently enabled
 * @enabled:            return argument telling if AppArmor is enabled
 *
 * If the AppArmor module is not loaded, or AppArmor is disabled in the
 * kernel, set @enabledp to 'false', otherwise set it to 'true'.
 *
 * Returns: 0 if check succeeded, or negative error code on failure.
 */
int bus_apparmor_is_enabled(bool *enabledp) {
        _c_cleanup_(c_fclosep) FILE *f = NULL;
        char buffer[LINE_MAX] = {};
        bool enabled;

        f = fopen("/sys/module/apparmor/parameters/enabled", "re");
        if (f) {
                errno = 0;
                if (!fgets(buffer, sizeof(buffer), f)) {
                        if (ferror(f))
                                return error_origin(-c_errno());
                }

                switch (buffer[0]) {
                        case 'Y':
                                enabled = true;
                                break;
                        case 'N':
                                enabled = false;
                                break;
                        default:
                                return error_origin(-EIO);
                }
        } else if (errno == ENOENT) {
                enabled = false;
        } else {
                return error_origin(-errno);
        }

        *enabledp = enabled;
        return 0;
}

/**
 * bus_apparmor_dbus_supported() - check for apparmor dbus support
 * @supported:            return argument telling if AppArmor DBus is supported
 *
 * If the AppArmor module is not loaded, or AppArmor does not support DBus,
 * set @supportedp to 'false', otherwise set it to 'true'.
 *
 * Returns: 0 if check succeeded, or negative error code on failure.
 */
int bus_apparmor_dbus_supported(bool *supportedp) {
        _c_cleanup_(c_fclosep) FILE *f = NULL;
        char buffer[LINE_MAX] = {};
        bool supported;

        f = fopen("/sys/kernel/security/apparmor/features/dbus/mask", "re");
        if (f) {
                errno = 0;
                if (!fgets(buffer, sizeof(buffer), f)) {
                        if (ferror(f))
                                return error_origin(-c_errno());
                }

                if (strstr(buffer, "acquire") && strstr(buffer, "send") && strstr(buffer, "receive"))
                        supported = true;
                else
                        supported = false;
        } else if (errno == ENOENT) {
                supported = false;
        } else {
                return error_origin(-errno);
        }

        *supportedp = supported;
        return 0;
}

static inline bool is_apparmor_enabled(BusAppArmorRegistry *registry) {
        return registry->bustype ? true : false;
}

static int bus_apparmor_log(const char *fmt, ...) {
        _c_cleanup_(c_freep) char *message = NULL;
        va_list ap;
        int r;

        va_start(ap, fmt);
        r = vasprintf(&message, fmt, ap);
        va_end(ap);
        if (r < 0)
                return r;

        /* XXX: we don't have access to any context, so can't find
         * the right UID to use, follow dbus-daemon(1) and use our
         * own. */
        r = util_audit_log(UTIL_AUDIT_TYPE_AVC, message, getuid());
        if (r)
                return error_fold(r);

        return 0;
}

/**
 * bus_apparmor_registry_new() - create a new AppArmor registry
 * @registryp:          pointer to the new registry
 * @fallback_context:   fallback security context for queries against this registry
 *
 * Return: 0 on success, or a negative error code on failure.
 */
int bus_apparmor_registry_new(struct BusAppArmorRegistry **registryp, const char *fallback_context) {
        _c_cleanup_(bus_apparmor_registry_unrefp) BusAppArmorRegistry *registry = NULL;
        size_t n_fallback_context = strlen(fallback_context) + 1;

        registry = malloc(sizeof(*registry) + n_fallback_context);
        if (!registry)
                return error_origin(-ENOMEM);

        registry->n_refs = REF_INIT;
        registry->fallback_context = (char *)(registry + 1);
        memcpy((char *)registry->fallback_context, fallback_context, n_fallback_context);

        *registryp = registry;
        registry = NULL;
        return 0;
}

static void bus_apparmor_registry_free(_Atomic unsigned long *n_refs, void *userdata) {
        BusAppArmorRegistry *registry = c_container_of(n_refs, BusAppArmorRegistry, n_refs);

        free(registry->bustype);
        free(registry);
}

BusAppArmorRegistry *bus_apparmor_registry_ref(BusAppArmorRegistry *registry) {
        if (registry)
                ref_inc(&registry->n_refs);

        return registry;
}

BusAppArmorRegistry *bus_apparmor_registry_unref(BusAppArmorRegistry *registry) {
        if (registry)
                ref_dec(&registry->n_refs, bus_apparmor_registry_free, NULL);

        return NULL;
}

int bus_apparmor_set_bus_type(BusAppArmorRegistry *registry, const char* bustype) {
        c_assert(!registry->bustype);

        registry->bustype = strdup(bustype);
        if (!registry->bustype)
                return error_origin(-ENOMEM);
        return 0;
}

static bool is_unconfined(const char *context) {
        return !strcmp(context, "unconfined");
}

static bool is_complain(const char *mode) {
        if (mode == NULL) return false;
        return !strcmp(mode, "complain");
}

static const char* allowstr(bool allow) {
        return allow ? "ALLOWED" : "DENIED";
}

static int build_service_query(char **query, const char *security_label,
                               const char *bustype, const char *name) {
        char *qstr;
        int i = 0, len;

        len = AA_QUERY_CMD_LABEL_SIZE;
        len += strlen(security_label) + 1;
        len += 1; /* AA_CLASS_DBUS */
        len += strlen(bustype) + 1;
        len += strlen(name) + 1;
        qstr = malloc(len);
        if (!qstr)
                return error_origin(-ENOMEM);

        i += AA_QUERY_CMD_LABEL_SIZE;
        strcpy(qstr+i, security_label);
        i += strlen(security_label) + 1;
        qstr[i++] = AA_CLASS_DBUS;
        strcpy(qstr+i, bustype);
        i += strlen(bustype) + 1;
        strcpy(qstr+i, name);

        *query = qstr;
        return len-1;
}

static int build_message_query_name(char **query, const char *security_label,
                                    const char *bustype, const char *name,
                                    const char *receiver_context,
                                    const char *path, const char *interface, const char *method) {
        char *qstr;
        int i = 0, len;

        len = AA_QUERY_CMD_LABEL_SIZE;
        len += strlen(security_label) + 1;
        len += 1; /* AA_CLASS_DBUS */
        len += strlen(bustype) + 1;
        len += strlen(receiver_context) + 1;
        len += strlen(name) + 1;
        len += strlen(path) + 1;
        len += strlen(interface) + 1;
        len += strlen(method) + 1;

        qstr = malloc(len);
        if (!qstr)
                return error_origin(-ENOMEM);

        i += AA_QUERY_CMD_LABEL_SIZE;
        strcpy(qstr+i, security_label);
        i += strlen(security_label) + 1;
        qstr[i++] = AA_CLASS_DBUS;
        strcpy(qstr+i, bustype);
        i += strlen(bustype) + 1;
        strcpy(qstr+i, receiver_context);
        i += strlen(receiver_context) + 1;
        strcpy(qstr+i, name);
        i += strlen(name) + 1;
        strcpy(qstr+i, path);
        i += strlen(path) + 1;
        strcpy(qstr+i, interface);
        i += strlen(interface) + 1;
        strcpy(qstr+i, method);

        *query = qstr;
        return len-1;
}

static int build_eavesdrop_query(char **query, const char *security_label, const char *bustype) {
        char *qstr;
        int i = 0, len;

        len = AA_QUERY_CMD_LABEL_SIZE;
        len += strlen(security_label) + 1;
        len += 1; /* AA_CLASS_DBUS */
        len += strlen(bustype) + 1;
        qstr = malloc(len);
        if (!qstr)
                return error_origin(-ENOMEM);

        i += AA_QUERY_CMD_LABEL_SIZE;
        strcpy(qstr+i, security_label);
        i += strlen(security_label) + 1;
        qstr[i++] = AA_CLASS_DBUS;
        strcpy(qstr+i, bustype);

        *query = qstr;
        return len-1;
}

static int apparmor_message_query_name(bool check_send, const char *security_label,
                                       const char *bustype, const char *receiver_context,
                                       const char *name, const char *path, const char *interface,
                                       const char *method, int *allow, int *audit) {
        _c_cleanup_(c_freep) char *qstr = NULL;
        int r;

        r = build_message_query_name(&qstr, security_label, bustype, receiver_context,
                                     name, path, interface, method);
        if (r < 0)
                return error_origin(r);

        r = aa_query_label(check_send ? AA_DBUS_SEND : AA_DBUS_RECEIVE, qstr, r, allow, audit);
        if (r < 0)
                return error_origin(-errno);

        return r;
}

static int apparmor_message_query(bool check_send, const char *security_label, const char *bustype,
                                  const char *receiver_context, NameSet *nameset,
                                  uint64_t subject_id, const char *path, const char *interface,
                                  const char *method, int *allow, int *audit) {
        NameOwnership *ownership;
        int i, r, audit_tmp = 0;

        if (!nameset) {
                r = apparmor_message_query_name(check_send, security_label, bustype,
                                                receiver_context, "org.freedesktop.DBus",
                                                path, interface, method, allow, audit);
        } else if (nameset->type == NAME_SET_TYPE_OWNER) {
                if (c_rbtree_is_empty(&nameset->owner->ownership_tree)) {
                        struct Address addr;
                        address_init_from_id(&addr, subject_id);
                        r = apparmor_message_query_name(check_send, security_label, bustype,
                                                        receiver_context, address_to_string(&addr),
                                                        path, interface, method, allow, audit);
                } else {
                        /*
                         * A set of owned names is given. In this case, we iterate all
                         * of them and match against each. Note that this matches even
                         * on non-primary name owners.
                         */
                        c_rbtree_for_each_entry(ownership, &nameset->owner->ownership_tree, owner_node) {
                                r = apparmor_message_query_name(check_send, security_label,
                                                                bustype, receiver_context,
                                                                ownership->name->name, path,
                                                                interface, method, allow, &audit_tmp);
                                if (r < 0)
                                        return r;
                                if (!allow)
                                        return r;
                                if (audit_tmp)
                                        *audit = 1;
                        }
                }
        } else if (nameset->type == NAME_SET_TYPE_SNAPSHOT) {
                /*
                 * An ownership-snapshot is given. Again, we simply iterate the
                 * names and match each. Note that the snapshot must contain
                 * queued names as well, since the policy matches on it.
                 */
                for (i = 0; i < nameset->snapshot->n_names; ++i) {
                        r = apparmor_message_query_name(check_send, security_label, bustype,
                                                        receiver_context,
                                                        nameset->snapshot->names[i]->name,
                                                        path, interface, method, allow, &audit_tmp);
                        if (r < 0)
                                return r;
                        if (!allow)
                                return r;
                        if (audit_tmp)
                                *audit = 1;
                }
        } else if (nameset->type != NAME_SET_TYPE_EMPTY) {
                c_assert(0);
                r = -EINVAL;
        }

        return r;
}

/**
 * bus_apparmor_check_own() - check if the given transaction is allowed
 * @registry:           AppArmor registry to operate on
 * @context:            security context requesting the name
 * @name:               name to be owned
 *
 * Check if the given owner context is allowed to own the given name.
 *
 * The contexts are pinned when peers connect, and as such could in principle
 * become invalid in case a new policy is loaded that does not know the
 * old labels. In this case we treat this as if the ownership request was
 * denied.
 *
 * Return: 0 if the ownership is allowed, BUS_APPARMOR_E_DENIED if it is not,
 *         or a negative error code on failure.
 */
int bus_apparmor_check_own(struct BusAppArmorRegistry *registry,
                           const char *owner_context,
                           const char *name) {
        _c_cleanup_(c_freep) char *condup = NULL;
        char *security_label, *security_mode;
        _c_cleanup_(c_freep) char *qstr = NULL;
        int r;
        /* the AppArmor API uses pointers to int for pointers to boolean */
        int allow = false, audit = true;

        if (!is_apparmor_enabled(registry))
                return 0;

        condup = strdup(owner_context);
        if (!condup)
                return error_origin(-ENOMEM);

        security_label = aa_splitcon(condup, &security_mode);

        r = build_service_query(&qstr, security_label, registry->bustype, name);
        if (r < 0)
                return error_origin(r);

        r = aa_query_label(AA_DBUS_BIND, qstr, r, &allow, &audit);
        if (r < 0)
                return error_origin(-errno);

        if (audit)
                bus_apparmor_log("apparmor=\"%s\" operation=\"dbus_bind\" bus=\"%s\" name=\"%s\"", allowstr(allow), registry->bustype, name);

        if (is_complain(security_mode))
                allow = 1;

        if (!allow)
                return BUS_APPARMOR_E_DENIED;

        return 0;
}

/**
 * bus_apparmor_check_xmit() - check if the given transaction is allowed
 * @registry:           AppArmor registry to operate on
 * @check_send:         true if sending should be checked, false is receiving should be checked
 * @sender_context:     security context of the sender
 * @receiver_context:   security context of the receiver, or NULL
 * @subject:            List of names
 * @subject_id:         Unique ID of the subject
 * @path:               Dbus object path
 * @interface:          DBus method interface
 * @method:             DBus method that is being called
 *
 * Check if the given sender context is allowed to send/receive a message
 * to the given receiver context. If the any context is given as NULL,
 * the per-registry fallback context is used instead.
 *
 * The contexts are pinned when peers connect, and as such could in principle
 * become invalid in case a new policy is loaded that does not know the
 * old labels. In this case we treat this as if the transaction was
 * denied.
 *
 * In case multiple names are available all are being checked and the function
 * will deny access if any of them is denied by AppArmor.
 *
 * Return: 0 if the transaction is allowed, BUS_APPARMOR_E_DENIED if it is not,
 *         or a negative error code on failure.
 */
int bus_apparmor_check_xmit(BusAppArmorRegistry *registry,
                            bool check_send,
                            const char *sender_context,
                            const char *receiver_context,
                            NameSet *subject,
                            uint64_t subject_id,
                            const char *path,
                            const char *interface,
                            const char *method) {
        _c_cleanup_(c_freep) char *sender_context_dup = strdup(sender_context ?: registry->fallback_context);
        _c_cleanup_(c_freep) char *receiver_context_dup = strdup(receiver_context ?: registry->fallback_context);
        char *sender_security_label, *sender_security_mode;
        char *receiver_security_label, *receiver_security_mode;
        const char *direction = check_send ? "send" : "receive";
        int r;
        /* the AppArmor API uses pointers to int for pointers to boolean */
        int allow = false, audit = true;

        if (!is_apparmor_enabled(registry))
                return 0;

        if (!sender_context_dup || !receiver_context_dup)
                return -ENOMEM;

        sender_security_label = aa_splitcon(sender_context_dup, &sender_security_mode);
        receiver_security_label = aa_splitcon(receiver_context_dup, &receiver_security_mode);

        if (is_unconfined(sender_security_label) && is_unconfined(receiver_security_label))
                return 0;

        r = apparmor_message_query(check_send,
                                   check_send ? sender_security_label : receiver_security_label,
                                   registry->bustype,
                                   check_send ? receiver_security_label : sender_security_label,
                                   subject, subject_id, path, interface, method, &allow, &audit);
        if (r < 0)
                return error_origin(r);

        if (audit)
                bus_apparmor_log("apparmor=\"%s\" operation=\"dbus_%s\" bus=\"%s\" path=\"%s\" interface=\"%s\" method=\"%s\"", allowstr(allow), direction, registry->bustype, path, interface, method);

        if (is_complain(check_send ? sender_security_mode : receiver_security_mode))
                allow = 1;

        if (!allow)
                return BUS_APPARMOR_E_DENIED;

        return 0;
}

/**
 * bus_apparmor_check_eavesdrop() - check if the given context may eavesdrop
 * @registry:           AppArmor registry to operate on
 * @context:            security context that wants to eavesdrop
 *
 * Check if the given sender context is allowed to do eavesdropping.
 *
 * Return: 0 if the transaction is allowed, BUS_APPARMOR_E_DENIED if it is not,
 *         or a negative error code on failure.
 */
int bus_apparmor_check_eavesdrop(BusAppArmorRegistry *registry,
                                 const char *context)
{
        _c_cleanup_(c_freep) char *condup = strdup(context);
        char *security_label, *security_mode;
        _c_cleanup_(c_freep) char *qstr = NULL;
        int r;
        /* the AppArmor API uses pointers to int for pointers to boolean */
        int allow = false, audit = true;

        if (!is_apparmor_enabled(registry) || is_unconfined(context))
                return 0;

        if (!condup)
                return -ENOMEM;

        security_label = aa_splitcon(condup, &security_mode);

        r = build_eavesdrop_query(&qstr, security_label, registry->bustype);
        if (r < 0)
                return error_origin(r);

        r = aa_query_label(AA_DBUS_EAVESDROP, qstr, r, &allow, &audit);
        if (r < 0)
                return error_origin(-errno);

        if (audit)
                bus_apparmor_log("apparmor=\"%s\" operation=\"dbus_eavesdrop\" bus=\"%s\" label=\"%s\"", allowstr(allow), registry->bustype, context);

        if (is_complain(security_mode))
                allow = 1;

        if (!allow)
                return BUS_APPARMOR_E_DENIED;

        return 0;
}
