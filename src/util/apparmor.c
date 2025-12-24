/*
 * Bus AppArmor Helpers
 *
 * Required AppArmor kernel support is available in upstream linux as of
 * version 6.17 (October 2025).
 */

#include <c-rbtree.h>
#include <c-stdaux.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/apparmor.h>
#include "bus/name.h"
#include "util/apparmor.h"
#include "util/audit.h"
#include "util/error.h"
#include "util/ref.h"
#include "util/string.h"

struct BusAppArmorRegistry {
        _Atomic unsigned long n_refs;
        char *bustype;
        char fallback_context[];
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

/**
 * bus_apparmor_registry_new() - create a new AppArmor registry
 * @registryp:          output pointer to the new registry
 * @fallback_context:   fallback security context for queries against this registry
 *
 * Return: 0 on success, or a negative error code on failure.
 */
int bus_apparmor_registry_new(struct BusAppArmorRegistry **registryp, const char *fallback_context) {
        _c_cleanup_(bus_apparmor_registry_unrefp) BusAppArmorRegistry *registry = NULL;
        size_t n_fallback_context;

        n_fallback_context = strlen(fallback_context);
        registry = calloc(1, sizeof(*registry) + n_fallback_context + 1);
        if (!registry)
                return error_origin(-ENOMEM);

        registry->n_refs = REF_INIT;
        strcpy(registry->fallback_context, fallback_context);

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

int bus_apparmor_set_bus_type(BusAppArmorRegistry *registry, const char *bustype) {
        char *dup = NULL;

        if (bustype) {
                dup = strdup(bustype);
                if (!dup)
                        return error_origin(-ENOMEM);
        }

        free(registry->bustype);
        registry->bustype = dup;

        return 0;
}

static int bus_apparmor_log(BusAppArmorRegistry *registry, const char *fmt, ...) {
        _c_cleanup_(c_freep) char *message = NULL;
        va_list ap;
        int r;

        va_start(ap, fmt);
        r = vasprintf(&message, fmt, ap);
        va_end(ap);
        if (r < 0)
                return error_origin(-errno);

        /* XXX: we don't have access to any context, so can't find
         * the right UID to use, follow dbus-daemon(1) and use our
         * own. */
        r = util_audit_log(UTIL_AUDIT_TYPE_AVC, message, getuid());
        if (r != UTIL_AUDIT_E_UNAVAILABLE) // XXX: use a log fallback
                return error_fold(r);

        return 0;
}

static bool is_unconfined(const char *label, const char *mode) {
        return string_equal(mode, "unconfined") ||
                (!mode && string_equal(label, "unconfined"));
}

static int build_service_query(
        char **queryp,
        size_t *n_queryp,
        const char *security_label,
        const char *bustype,
        const char *name
) {
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

        *queryp = qstr;
        *n_queryp = len - 1;
        return 0;
}

static int build_message_query_name(
        char **queryp,
        size_t *n_queryp,
        const char *security_label,
        const char *bustype,
        const char *name,
        const char *receiver_context,
        const char *path,
        const char *interface,
        const char *method
) {
        char *qstr;
        int i = 0, len;

        len = AA_QUERY_CMD_LABEL_SIZE;
        len += strlen(security_label) + 1;
        len += 1; /* AA_CLASS_DBUS */
        len += strlen(bustype) + 1;
        len += strlen(receiver_context) + 1;
        len += strlen(name) + 1;
        len += strlen(path) + 1;
        if (interface)
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
        if (interface) {
                strcpy(qstr+i, interface);
                i += strlen(interface) + 1;
        }
        strcpy(qstr+i, method);

        *queryp = qstr;
        *n_queryp = len - 1;
        return 0;
}

static int build_eavesdrop_query(
        char **queryp,
        size_t *n_queryp,
        const char *security_label,
        const char *bustype
) {
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

        *queryp = qstr;
        *n_queryp = len - 1;
        return 0;
}

static int apparmor_message_query_name(
        bool check_send,
        const char *security_label,
        const char *bustype,
        const char *receiver_context,
        const char *name,
        const char *path,
        const char *interface,
        const char *method,
        int *allow,
        int *audit
) {
        _c_cleanup_(c_freep) char *qstr = NULL;
        size_t n_qstr;
        int r;

        r = build_message_query_name(
                &qstr,
                &n_qstr,
                security_label,
                bustype,
                receiver_context,
                name,
                path,
                interface,
                method
        );
        if (r)
                return error_fold(r);

        r = aa_query_label(
                check_send ? AA_DBUS_SEND : AA_DBUS_RECEIVE,
                qstr,
                n_qstr,
                allow,
                audit
        );
        if (r)
                return error_origin(-c_errno());

        return 0;
}

static int apparmor_message_query(
        bool check_send,
        const char *security_label,
        const char *bustype,
        const char *receiver_context,
        NameSet *nameset,
        uint64_t subject_id,
        const char *path,
        const char *interface,
        const char *method,
        int *allow,
        int *audit
) {
        NameOwnership *ownership;
        int r, audit_tmp = 0;
        size_t i;

        if (!nameset) {
                r = apparmor_message_query_name(
                        check_send, security_label, bustype,
                        receiver_context, "org.freedesktop.DBus",
                        path, interface, method, allow, audit
                );
                if (r)
                        return error_fold(r);
        } else if (nameset->type == NAME_SET_TYPE_OWNER) {
                if (c_rbtree_is_empty(&nameset->owner->ownership_tree)) {
                        struct Address addr;

                        address_init_from_id(&addr, subject_id);

                        r = apparmor_message_query_name(
                                check_send, security_label, bustype,
                                receiver_context, address_to_string(&addr),
                                path, interface, method, allow, audit
                        );
                        if (r)
                                return error_fold(r);
                } else {
                        *allow = 0;
                        *audit = 0;

                        c_rbtree_for_each_entry(ownership, &nameset->owner->ownership_tree, owner_node) {
                                r = apparmor_message_query_name(
                                        check_send, security_label,
                                        bustype, receiver_context,
                                        ownership->name->name, path,
                                        interface, method, allow, &audit_tmp
                                );
                                if (r)
                                        return error_fold(r);
                                if (audit_tmp)
                                        *audit = 1;
                                if (!*allow)
                                        return 0;
                        }
                }
        } else if (nameset->type == NAME_SET_TYPE_SNAPSHOT) {
                *allow = 0;
                *audit = 0;

                for (i = 0; i < nameset->snapshot->n_names; ++i) {
                        r = apparmor_message_query_name(
                                check_send, security_label, bustype,
                                receiver_context,
                                nameset->snapshot->names[i]->name,
                                path, interface, method, allow, &audit_tmp
                        );
                        if (r)
                                return error_fold(r);
                        if (audit_tmp)
                                *audit = 1;
                        if (!*allow)
                                return 0;
                }
        } else if (nameset->type == NAME_SET_TYPE_EMPTY) {
                *allow = 0;
                *audit = 1;
        } else {
                return error_origin(-ENOTRECOVERABLE);
        }

        return 0;
}

/**
 * bus_apparmor_check_own() - check if the given transaction is allowed
 * @registry:           AppArmor registry to operate on
 * @owner_context:      security context requesting the name
 * @name:               name to be owned
 *
 * Check if the given owner context is allowed to own the given name.
 *
 * Return: 0 if the ownership is allowed, BUS_APPARMOR_E_DENIED if it is not,
 *         or a negative error code on failure.
 */
int bus_apparmor_check_own(struct BusAppArmorRegistry *registry,
                           const char *owner_context,
                           const char *name) {
        _c_cleanup_(c_freep) char *condup = NULL, *qstr = NULL;
        char *security_label, *security_mode;
        int r, allow, audit;
        size_t n_qstr;

        if (!registry->bustype)
                return 0;

        condup = strdup(owner_context);
        if (!condup)
                return error_origin(-ENOMEM);

        security_label = aa_splitcon(condup, &security_mode);

        if (is_unconfined(security_label, security_mode))
                return 0;

        r = build_service_query(
                &qstr,
                &n_qstr,
                security_label,
                registry->bustype,
                name
        );
        if (r)
                return error_fold(r);

        r = aa_query_label(AA_DBUS_BIND, qstr, n_qstr, &allow, &audit);
        if (r)
                return error_origin(-c_errno());

        if (string_equal(security_mode, "complain"))
                allow = true;

        if (audit)
                bus_apparmor_log(
                        registry,
                        "apparmor=\"%s\" operation=\"dbus_bind\" "
                        "bus=\"%s\" name=\"%s\" mask=\"bind\"",
                        allow ? "ALLOWED" : "DENIED",
                        registry->bustype,
                        name
                );

        return allow ? 0 : BUS_APPARMOR_E_DENIED;
}

/**
 * bus_apparmor_check_send() - check if the given transaction is allowed
 * @registry:           AppArmor registry to operate on
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
 * In case multiple names are available all are being checked and the function
 * will deny access if any of them is denied by AppArmor.
 *
 * Return: 0 if the transaction is allowed, BUS_APPARMOR_E_DENIED if it is not,
 *         or a negative error code on failure.
 */
int bus_apparmor_check_send(BusAppArmorRegistry *registry,
                            const char *sender_context,
                            const char *receiver_context,
                            NameSet *subject,
                            uint64_t subject_id,
                            const char *path,
                            const char *interface,
                            const char *method) {
        _c_cleanup_(c_freep) char *sender_context_dup = NULL;
        _c_cleanup_(c_freep) char *receiver_context_dup = NULL;
        char *sender_security_label, *sender_security_mode;
        char *receiver_security_label, *receiver_security_mode;
        int r, src_allow = false, src_audit = true, dst_allow = false, dst_audit = true;

        if (!registry->bustype)
                return 0;

        sender_context_dup = strdup(sender_context ?: registry->fallback_context);
        if (!sender_context_dup)
                return error_origin(-ENOMEM);
        receiver_context_dup = strdup(receiver_context ?: registry->fallback_context);
        if (!receiver_context_dup)
                return error_origin(-ENOMEM);

        sender_security_label = aa_splitcon(sender_context_dup, &sender_security_mode);
        receiver_security_label = aa_splitcon(receiver_context_dup, &receiver_security_mode);

        if (is_unconfined(sender_security_label, sender_security_mode)) {
                src_allow = true;
                src_audit = false;
        } else {
                r = apparmor_message_query(true,
                                           sender_security_label,
                                           registry->bustype,
                                           receiver_security_label,
                                           subject, subject_id, path,
                                           interface, method, &src_allow, &src_audit);

                if (r)
                        return error_fold(r);
        }

        if (is_unconfined(receiver_security_label, receiver_security_mode)) {
                dst_allow = true;
                dst_audit = false;
        } else {
                r = apparmor_message_query(false,
                                           receiver_security_label,
                                           registry->bustype,
                                           sender_security_label,
                                           subject, subject_id, path,
                                           interface, method, &dst_allow, &dst_audit);
                if (r)
                        return error_fold(r);
        }

        if (string_equal(sender_security_mode, "complain"))
                src_allow = 1;
        if (string_equal(receiver_security_mode, "complain"))
                dst_allow = 1;

        if (src_audit) {
                bus_apparmor_log(registry,
                        "apparmor=\"%s\" operation=\"dbus_method_call\" "
                        "bus=\"%s\" path=\"%s\" interface=\"%s\" method=\"%s\" "
                        "mask=\"send\" label=\"%s\" peer_label=\"%s\"",
                        src_allow ? "ALLOWED" : "DENIED",
                        registry->bustype,
                        path,
                        interface,
                        method,
                        sender_security_label,
                        receiver_security_label
                );
        }

        if (dst_audit) {
                bus_apparmor_log(registry,
                        "apparmor=\"%s\" operation=\"dbus_method_call\" "
                        "bus=\"%s\" path=\"%s\" interface=\"%s\" method=\"%s\" "
                        "mask=\"receive\" label=\"%s\" peer_label=\"%s\"",
                        dst_allow ? "ALLOWED" : "DENIED",
                        registry->bustype,
                        path,
                        interface,
                        method,
                        receiver_security_label,
                        sender_security_label
                );
        }

        return (src_allow && dst_allow) ? 0 : BUS_APPARMOR_E_DENIED;
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
        _c_cleanup_(c_freep) char *condup = NULL, *qstr = NULL;
        char *security_label, *security_mode;
        int r, allow, audit;
        size_t n_qstr;

        if (!registry->bustype)
                return 0;

        condup = strdup(context);
        if (!condup)
                return error_origin(-ENOMEM);

        security_label = aa_splitcon(condup, &security_mode);

        if (is_unconfined(security_label, security_mode))
                return 0;

        r = build_eavesdrop_query(
                &qstr,
                &n_qstr,
                security_label,
                registry->bustype
        );
        if (r)
                return error_fold(r);

        r = aa_query_label(AA_DBUS_EAVESDROP, qstr, n_qstr, &allow, &audit);
        if (r)
                return error_origin(-c_errno());

        if (string_equal(security_mode, "complain"))
                allow = 1;

        if (audit)
                bus_apparmor_log(
                        registry,
                        "apparmor=\"%s\" operation=\"dbus_eavesdrop\" "
                        "bus=\"%s\" label=\"%s\"",
                        allow ? "ALLOWED" : "DENIED",
                        registry->bustype,
                        context
                );

        return allow ? 0 : BUS_APPARMOR_E_DENIED;
}
