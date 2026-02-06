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
#include "dbus/protocol.h"
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
                                return error_origin(-errno);
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
                                return error_origin(-errno);
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
int bus_apparmor_registry_new(BusAppArmorRegistry **registryp, const char *fallback_context) {
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

static int bus_apparmor_log(
        BusAppArmorRegistry *registry,
        uid_t uid,
        const char *fmt,
        ...
) {
        _c_cleanup_(c_freep) char *message = NULL;
        va_list ap;
        int r;

        va_start(ap, fmt);
        r = vasprintf(&message, fmt, ap);
        va_end(ap);
        if (r < 0)
                return error_origin(-errno);

        r = util_audit_log(UTIL_AUDIT_TYPE_AVC, message, uid);
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
        i += strlen(name) + 1;

        *queryp = qstr;
        *n_queryp = i - 1;
        return 0;
}

static int build_message_query(
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
        if (path)
                len += strlen(path) + 1;
        if (interface)
                len += strlen(interface) + 1;
        if (method)
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
        if (path) {
                strcpy(qstr+i, path);
                i += strlen(path) + 1;
        }
        if (interface) {
                strcpy(qstr+i, interface);
                i += strlen(interface) + 1;
        }
        if (method) {
                strcpy(qstr+i, method);
                i += strlen(method) + 1;
        }

        *queryp = qstr;
        *n_queryp = i - 1;
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
        i += strlen(bustype) + 1;

        *queryp = qstr;
        *n_queryp = i - 1;
        return 0;
}

static int apparmor_message_query(
        uint32_t aa_mask,
        const char *security_label,
        const char *bustype,
        const char *receiver_context,
        const char *src_or_dst,
        const char *path,
        const char *interface,
        const char *method,
        int *allow,
        int *audit
) {
        _c_cleanup_(c_freep) char *qstr = NULL;
        size_t n_qstr;
        int r;

        r = build_message_query(
                &qstr,
                &n_qstr,
                security_label,
                bustype,
                receiver_context,
                src_or_dst,
                path,
                interface,
                method
        );
        if (r)
                return error_fold(r);

        r = aa_query_label(
                aa_mask,
                qstr,
                n_qstr,
                allow,
                audit
        );
        if (r)
                return error_origin(-errno);

        return 0;
}

/**
 * bus_apparmor_check_own() - check if the given transaction is allowed
 * @registry:           AppArmor registry to operate on
 * @context:            security context requesting the name
 * @uid:                uid of the requester
 * @name:               name to be owned
 *
 * Check if the given owner context is allowed to own the given name.
 *
 * Return: 0 if the ownership is allowed, BUS_APPARMOR_E_DENIED if it is not,
 *         or a negative error code on failure.
 */
int bus_apparmor_check_own(
        BusAppArmorRegistry *registry,
        const char *context,
        uid_t uid,
        const char *name
) {
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
                return error_origin(-errno);

        if (string_equal(security_mode, "complain"))
                allow = true;

        if (audit) {
                r = bus_apparmor_log(
                        registry,
                        uid,
                        "apparmor=\"%s\""
                        " operation=\"dbus_bind\""
                        " bus=\"%s\""
                        " name=\"%s\""
                        " mask=\"bind\"",
                        " label=\"%s\"",
                        allow ? "ALLOWED" : "DENIED",
                        registry->bustype,
                        name,
                        security_label
                );
                if (r)
                        return error_fold(r);
        }

        return allow ? 0 : BUS_APPARMOR_E_DENIED;
}

/**
 * bus_apparmor_check_send() - check if the given transaction is allowed
 * @registry:           AppArmor registry to operate on
 * @sender_context:     security context of the sender
 * @sender_uid:         uid of the sender
 * @sender_id:          DBus ID of the sender
 * @receiver_context:   security context of the receiver, or NULL
 * @destination:        DBus message destination, or NULL
 * @path:               DBus object path
 * @interface:          DBus method interface, or NULL
 * @method:             DBus method that is being called, or NULL
 * @type:               DBus message type
 *
 * Check if the given sender context is allowed to send/receive a message
 * to the given receiver context. If the any context is given as NULL,
 * the per-registry fallback context is used instead.
 *
 * Return: 0 if the transaction is allowed, BUS_APPARMOR_E_DENIED if it is not,
 *         or a negative error code on failure.
 */
int bus_apparmor_check_send(
        BusAppArmorRegistry *registry,
        const char *sender_context,
        uid_t sender_uid,
        uint64_t sender_id,
        const char *receiver_context,
        const char *destination,
        const char *path,
        const char *interface,
        const char *method,
        unsigned int type
) {
        _c_cleanup_(c_freep) char *sender_context_dup = NULL;
        _c_cleanup_(c_freep) char *receiver_context_dup = NULL;
        struct Address sender_addr;
        const char *op = NULL, *sender_name = NULL;
        char *sender_security_label, *sender_security_mode;
        char *receiver_security_label, *receiver_security_mode;
        int r, src_allow = false, src_audit = true, dst_allow = false, dst_audit = true;

        if (!registry->bustype)
                return 0;

        address_init_from_id(&sender_addr, sender_id);
        sender_name = address_to_string(&sender_addr);

        /*
         * dbus-daemon(1) uses this fallback, so we follow suit.
         * This is bogus for broadcasts (or any message without
         * destination), but lets keep compatibility.
         */
        destination = destination ?: "org.freedesktop.DBus";

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
                r = apparmor_message_query(
                        AA_DBUS_SEND,
                        sender_security_label,
                        registry->bustype,
                        receiver_security_label,
                        destination,
                        path,
                        interface,
                        method,
                        &src_allow,
                        &src_audit
                );
                if (r)
                        return error_fold(r);
        }

        if (is_unconfined(receiver_security_label, receiver_security_mode)) {
                dst_allow = true;
                dst_audit = false;
        } else {
                r = apparmor_message_query(
                        AA_DBUS_RECEIVE,
                        receiver_security_label,
                        registry->bustype,
                        sender_security_label,
                        sender_name,
                        path,
                        interface,
                        method,
                        &dst_allow,
                        &dst_audit
                );
                if (r)
                        return error_fold(r);
        }

        if (string_equal(sender_security_mode, "complain"))
                src_allow = 1;
        if (string_equal(receiver_security_mode, "complain"))
                dst_allow = 1;

        switch (type) {
        case DBUS_MESSAGE_TYPE_METHOD_CALL:
                op = "method_call";
                break;
        case DBUS_MESSAGE_TYPE_METHOD_RETURN:
                op = "method_return";
                break;
        case DBUS_MESSAGE_TYPE_ERROR:
                op = "error";
                break;
        case DBUS_MESSAGE_TYPE_SIGNAL:
                op = "signal";
                break;
        default:
                return error_origin(-ENOTRECOVERABLE);
        }

        if (src_audit) {
                r = bus_apparmor_log(
                        registry,
                        sender_uid,
                        "apparmor=\"%s\""
                        " operation=\"dbus_%s\""
                        " bus=\"%s\""
                        " path=\"%s\""
                        " interface=\"%s\""
                        " member=\"%s\""
                        " mask=\"send\""
                        " name=\"%s\""
                        " label=\"%s\""
                        " peer_label=\"%s\"",
                        src_allow ? "ALLOWED" : "DENIED",
                        op,
                        registry->bustype,
                        path ?: "",
                        interface ?: "",
                        method ?: "",
                        destination,
                        sender_security_label,
                        receiver_security_label
                );
                if (r)
                        return error_fold(r);
        }

        if (dst_audit) {
                r = bus_apparmor_log(
                        registry,
                        sender_uid,
                        "apparmor=\"%s\""
                        " operation=\"dbus_%s\""
                        " bus=\"%s\""
                        " path=\"%s\""
                        " interface=\"%s\""
                        " member=\"%s\""
                        " mask=\"receive\""
                        " name=\"%s\""
                        " label=\"%s\""
                        " peer_label=\"%s\"",
                        dst_allow ? "ALLOWED" : "DENIED",
                        op,
                        registry->bustype,
                        path ?: "",
                        interface ?: "",
                        method ?: "",
                        sender_name,
                        receiver_security_label,
                        sender_security_label
                );
                if (r)
                        return error_fold(r);
        }

        return (src_allow && dst_allow) ? 0 : BUS_APPARMOR_E_DENIED;
}

/**
 * bus_apparmor_check_eavesdrop() - check if the given context may eavesdrop
 * @registry:           AppArmor registry to operate on
 * @context:            security context that wants to eavesdrop
 * @uid:                uid of the calling user
 *
 * Check if the given sender context is allowed to do eavesdropping.
 *
 * Return: 0 if the transaction is allowed, BUS_APPARMOR_E_DENIED if it is not,
 *         or a negative error code on failure.
 */
int bus_apparmor_check_eavesdrop(
        BusAppArmorRegistry *registry,
        const char *context,
        uid_t uid
) {
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
                return error_origin(-errno);

        if (string_equal(security_mode, "complain"))
                allow = 1;

        if (audit) {
                r = bus_apparmor_log(
                        registry,
                        uid,
                        "apparmor=\"%s\""
                        " operation=\"dbus_eavesdrop\""
                        " bus=\"%s\""
                        " mask=\"eavesdrop\""
                        " label=\"%s\"",
                        allow ? "ALLOWED" : "DENIED",
                        registry->bustype,
                        security_label
                );
                if (r)
                        return error_fold(r);
        }

        return allow ? 0 : BUS_APPARMOR_E_DENIED;
}
