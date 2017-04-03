/*
 * DBus Driver
 */

#include <c-dvar.h>
#include <c-macro.h>
#include <stdlib.h>
#include "bus.h"
#include "dbus-message.h"
#include "driver.h"
#include "peer.h"

/* XXX: move to where it belongs */
#define DBUS_MESSAGE_TYPE_INVALID       (0)
#define DBUS_MESSAGE_TYPE_METHOD_CALL   (1)
#define DBUS_MESSAGE_TYPE_METHOD_REPLY  (2)
#define DBUS_MESSAGE_TYPE_ERROR         (3)
#define DBUS_MESSAGE_TYPE_SIGNAL        (4)

#define DBUS_MESSAGE_FIELD_INVALID      (0)
#define DBUS_MESSAGE_FIELD_PATH         (1)
#define DBUS_MESSAGE_FIELD_INTERFACE    (2)
#define DBUS_MESSAGE_FIELD_MEMBER       (3)
#define DBUS_MESSAGE_FIELD_ERROR_NAME   (4)
#define DBUS_MESSAGE_FIELD_REPLY_SERIAL (5)
#define DBUS_MESSAGE_FIELD_DESTINATION  (6)
#define DBUS_MESSAGE_FIELD_SENDER       (7)
#define DBUS_MESSAGE_FIELD_SIGNATURE    (8)
#define DBUS_MESSAGE_FIELD_UNIX_FDS     (9)

typedef struct DriverMethod DriverMethod;
typedef int (*DriverMethodFn) (Peer *peer, const char *signature, DBusMessage *message);

struct DriverMethod {
        const char *name;
        DriverMethodFn fn;
};

int driver_method_hello(Peer *peer, const char *signature, DBusMessage *message) {
        if (_c_unlikely_(peer_is_registered(peer)))
                return -EBADMSG;

        bus_register_peer(peer->bus, peer);

        return 0;
}

int driver_method_list_names(Peer *peer, const char *signature, DBusMessage *message) {
        return 0;
}

int driver_method_list_activatable_names(Peer *peer, const char *signature, DBusMessage *message) {
        return 0;
}

int driver_method_name_has_owner(Peer *peer, const char *signature, DBusMessage *message) {
        return 0;
}

int driver_method_start_service_by_name(Peer *peer, const char *signature, DBusMessage *message) {
        return 0;
}

int driver_method_update_activation_environment(Peer *peer, const char *signature, DBusMessage *message) {
        return 0;
}

int driver_method_get_name_owner(Peer *peer, const char *signature, DBusMessage *message) {
        return 0;
}

int driver_method_get_connection_unix_user(Peer *peer, const char *signature, DBusMessage *message) {
        return 0;
}

int driver_method_get_connection_unix_process_id(Peer *peer, const char *signature, DBusMessage *message) {
        return 0;
}

int driver_method_get_connection_credentials(Peer *peer, const char *signature, DBusMessage *message) {
        return 0;
}

int driver_method_get_adt_audit_session_data(Peer *peer, const char *signature, DBusMessage *message) {
        return 0;
}

int driver_method_get_connection_selinux_security_context(Peer *peer, const char *signature, DBusMessage *message) {
        return 0;
}

int driver_method_add_match(Peer *peer, const char *signature, DBusMessage *message) {
        return 0;
}

int driver_method_remove_match(Peer *peer, const char *signature, DBusMessage *message) {
        return 0;
}

int driver_method_get_id(Peer *peer, const char *signature, DBusMessage *message) {
        return 0;
}

int driver_method_become_monitor(Peer *peer, const char *signature, DBusMessage *message) {
        return 0;
}

/* XXX: use gperf */
static int driver_dispatch_method(Peer *peer, const char *method, const char *signature, DBusMessage *message) {
        static const DriverMethod methods[] = {
                { "Hello", driver_method_hello },
                { "ListNames", driver_method_list_names },
                { "ListActivatableNames", driver_method_list_activatable_names },
                { "NameHasOwner", driver_method_name_has_owner },
                { "StartServiceByName", driver_method_start_service_by_name },
                { "UpdateActivationEnvironment", driver_method_update_activation_environment },
                { "GetNameOwner", driver_method_get_name_owner },
                { "GetConnectionUnixUser", driver_method_get_connection_unix_user },
                { "GetConnectionUnixProcessID", driver_method_get_connection_unix_process_id },
                { "GetConnecitonCredentials", driver_method_get_connection_credentials },
                { "GetAdtAuditSessionData", driver_method_get_adt_audit_session_data },
                { "GetConnectionSELinuxSecurityContext", driver_method_get_connection_selinux_security_context },
                { "AddMatch", driver_method_add_match },
                { "RemoveMatch", driver_method_remove_match },
                { "GetId", driver_method_get_id },
                { "BecomeMonitor", driver_method_become_monitor },
        };

        if (_c_unlikely_(!peer_is_registered(peer)) &&
            strcmp(method, "Hello") != 0)
                return -EBADMSG;

        for (unsigned int i = 0; i < C_ARRAY_SIZE(methods); i++) {
                if (strcmp(methods[i].name, method) == 0)
                        return methods[i].fn(peer, signature, message);
        }

        return -ENOENT;
}

static int driver_handle_method_call_internal(Peer *peer,
                                              const char *interface,
                                              const char *member,
                                              const char *path,
                                              const char *signature,
                                              DBusMessage *message) {
        if (interface &&
            _c_unlikely_(strcmp(interface, "org.freedesktop.DBus") != 0))
                return -EBADMSG;

        return driver_dispatch_method(peer, member, signature, message);
}

static int driver_handle_method_call(Peer *peer,
                                     const char *destination,
                                     const char *interface,
                                     const char *member,
                                     const char *path,
                                     const char *signature,
                                     DBusMessage *message) {
        if (_c_unlikely_(!destination || !member || !path))
                return -EBADMSG;

        if (_c_unlikely_(strcmp(destination, "org.freedesktop.DBus") == 0))
                return driver_handle_method_call_internal(peer,
                                                          interface,
                                                          member,
                                                          path,
                                                          signature,
                                                          message);
        else if (_c_unlikely_(!peer_is_registered(peer)))
                return -EBADMSG;

        return 0;
}

static int driver_handle_method_reply(Peer *peer,
                                      const char *destination,
                                      uint32_t reply_serial,
                                      const char *signature,
                                      DBusMessage *message) {
        if (_c_unlikely_(!peer_is_registered(peer)))
                return -EBADMSG;

        return 0;
}

static int driver_handle_error(Peer *peer,
                               const char *destination,
                               uint32_t reply_serial,
                               const char *error_name,
                               const char *signature,
                               DBusMessage *message) {
        if (_c_unlikely_(!peer_is_registered(peer)))
                return -EBADMSG;

        return 0;
}

static int driver_handle_signal(Peer *peer,
                                const char *destination,
                                const char *interface,
                                const char *member,
                                const char *path,
                                const char *signature,
                                DBusMessage *message) {
        if (_c_unlikely_(!peer_is_registered(peer)))
                return -EBADMSG;

        return 0;
}

int driver_handle_message(Peer *peer, DBusMessage *message) {
        _c_cleanup_(c_dvar_type_freep) CDVarType *type = NULL;
        _c_cleanup_(c_dvar_freep) CDVar *v = NULL;
        const char *path = NULL,
                   *interface = NULL,
                   *member = NULL,
                   *error_name = NULL,
                   *destination = NULL,
                   *sender = NULL,
                   *signature = NULL;
        uint32_t reply_serial = 0, n_fds = 0;
        uint8_t field;
        int r;

        /*
         * XXX: Rather than allocating @type and @v, we should use their static
         *      versions on the stack, once provided by c-dvar.
         *      Also replace the NULL types in the dynamic readers below with
         *      their pre-allocated respective types.
         */

        r = c_dvar_type_new_from_string(&type, "(yyyyuua(yv))");
        if (r)
                return (r > 0) ? -ENOTRECOVERABLE : r;

        r = c_dvar_new(&v);
        if (r)
                return (r > 0) ? -ENOTRECOVERABLE : r;

        c_dvar_begin_read(v, message->big_endian, type, message->header, message->n_header);

        c_dvar_skip(v, "(yyyyuu[");

        while (c_dvar_more(v)) {
                /*
                 * XXX: What should we do on duplicates?
                 */

                c_dvar_read(v, "(y", &field);

                switch (field) {
                case DBUS_MESSAGE_FIELD_INVALID:
                        return -EBADMSG;
                case DBUS_MESSAGE_FIELD_PATH:
                        c_dvar_read(v, "<o>)", NULL, &path);
                        break;
                case DBUS_MESSAGE_FIELD_INTERFACE:
                        c_dvar_read(v, "<s>)", NULL, &interface);
                        break;
                case DBUS_MESSAGE_FIELD_MEMBER:
                        c_dvar_read(v, "<s>)", NULL, &member);
                        break;
                case DBUS_MESSAGE_FIELD_ERROR_NAME:
                        c_dvar_read(v, "<s>)", NULL, &error_name);
                        break;
                case DBUS_MESSAGE_FIELD_REPLY_SERIAL:
                        c_dvar_read(v, "<u>)", NULL, &reply_serial);
                        break;
                case DBUS_MESSAGE_FIELD_DESTINATION:
                        c_dvar_read(v, "<s>)", NULL, &destination);
                        break;
                case DBUS_MESSAGE_FIELD_SENDER:
                        /* XXX: check with dbus-daemon(1) on what to do */
                        c_dvar_read(v, "<s>)", NULL, &sender);
                        break;
                case DBUS_MESSAGE_FIELD_SIGNATURE:
                        c_dvar_read(v, "<g>)", NULL, &signature);
                        break;
                case DBUS_MESSAGE_FIELD_UNIX_FDS:
                        c_dvar_read(v, "<u>)", NULL, &n_fds);
                        break;
                default:
                        c_dvar_skip(v, "v)");
                        break;
                }
        }

        c_dvar_skip(v, "])");

        r = c_dvar_end_read(v);
        if (r)
                return (r > 0) ? -EBADMSG : r;

        if (_c_unlikely_(n_fds > message->n_fds))
                return -EBADMSG;
        while (_c_unlikely_(n_fds < message->n_fds))
                close(message->fds[-- message->n_fds]);

        switch (message->header->type) {
        case DBUS_MESSAGE_TYPE_INVALID:
                return -EBADMSG;
        case DBUS_MESSAGE_TYPE_METHOD_CALL:
                return driver_handle_method_call(peer,
                                                 destination,
                                                 interface,
                                                 member,
                                                 path,
                                                 signature,
                                                 message);
        case DBUS_MESSAGE_TYPE_METHOD_REPLY:
                return driver_handle_method_reply(peer,
                                                  destination,
                                                  reply_serial,
                                                  signature,
                                                  message);
        case DBUS_MESSAGE_TYPE_ERROR:
                return driver_handle_error(peer,
                                           destination,
                                           reply_serial,
                                           error_name,
                                           signature,
                                           message);
        case DBUS_MESSAGE_TYPE_SIGNAL:
                return driver_handle_signal(peer,
                                            destination,
                                            interface,
                                            member,
                                            path,
                                            signature,
                                            message);
        default:
                break;
        }

        return 0;
}

void driver_notify_name_owner_change(const char *name, Peer *old_peer, Peer *new_peer) {
        assert(old_peer || new_peer);
        assert(!old_peer || c_rbnode_is_linked(&old_peer->rb));
        assert(!new_peer || c_rbnode_is_linked(&new_peer->rb));
        assert(name || !old_peer || !new_peer);
}
