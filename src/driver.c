/*
 * DBus Driver
 */

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


typedef struct DriverMethod DriverMethod;
typedef int (*DriverMethodFn) (Peer *peer, DBusMessage *message);

struct DriverMethod {
        const char *name;
        DriverMethodFn fn;
};

int driver_method_hello(Peer *peer, DBusMessage *message) {
        bus_register_peer(peer->bus, peer);

        return 0;
}

int driver_method_list_names(Peer *peer, DBusMessage *message) {
        return 0;
}

int driver_method_list_activatable_names(Peer *peer, DBusMessage *message) {
        return 0;
}

int driver_method_name_has_owner(Peer *peer, DBusMessage *message) {
        return 0;
}

int driver_method_start_service_by_name(Peer *peer, DBusMessage *message) {
        return 0;
}

int driver_method_update_activation_environment(Peer *peer, DBusMessage *message) {
        return 0;
}

int driver_method_get_name_owner(Peer *peer, DBusMessage *message) {
        return 0;
}

int driver_method_get_connection_unix_user(Peer *peer, DBusMessage *message) {
        return 0;
}

int driver_method_get_connection_unix_process_id(Peer *peer, DBusMessage *message) {
        return 0;
}

int driver_method_get_connection_credentials(Peer *peer, DBusMessage *message) {
        return 0;
}

int driver_method_get_adt_audit_session_data(Peer *peer, DBusMessage *message) {
        return 0;
}

int driver_method_get_connection_selinux_security_context(Peer *peer, DBusMessage *message) {
        return 0;
}

int driver_method_add_match(Peer *peer, DBusMessage *message) {
        return 0;
}

int driver_method_remove_match(Peer *peer, DBusMessage *message) {
        return 0;
}

int driver_method_get_id(Peer *peer, DBusMessage *message) {
        return 0;
}

int driver_method_become_monitor(Peer *peer, DBusMessage *message) {
        return 0;
}

/* XXX: use gperf */
static int driver_dispatch_method(Peer *peer,
                                  const char *method,
                                  DBusMessage *message) {
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

        for (unsigned int i = 0; i < C_ARRAY_SIZE(methods); i++) {
                if (strcmp(methods[i].name, method) == 0)
                        return methods[i].fn(peer, message);
        }

        return -ENOENT;
}

static int driver_handle_method_call_internal(Peer *peer,
                                              const char *interface,
                                              const char *member,
                                              const char *path,
                                              const char *signature,
                                              DBusMessage *message) {
        if (interface && strcmp(interface, "org.freedesktop.DBus") != 0)
                return -EBADMSG;

        /* XXX: path/signature */

        return driver_dispatch_method(peer, member, message);
}

static int driver_handle_method_call(Peer *peer,
                                     const char *destination,
                                     const char *interface,
                                     const char *member,
                                     const char *path,
                                     const char *signature,
                                     DBusMessage *message) {
        if (!destination)
                return -EBADMSG;

        if (strcmp(destination, "org.freedesktop.DBus") == 0)
                return driver_handle_method_call_internal(peer,
                                                          interface,
                                                          member,
                                                          path,
                                                          signature,
                                                          message);

        return 0;
}

static int driver_handle_method_reply(Peer *peer,
                                      const char *destination,
                                      uint32_t reply_serial,
                                      const char *signature,
                                      DBusMessage *message) {
        return 0;
}

static int driver_handle_error(Peer *peer,
                               const char *destination,
                               uint32_t reply_serial,
                               const char *error_name,
                               const char *signature,
                               DBusMessage *message) {
        return 0;
}

static int driver_handle_signal(Peer *peer,
                                const char *destination,
                                const char *interface,
                                const char *member,
                                const char *path,
                                const char *signature,
                                DBusMessage *message) {
        return 0;
}

int driver_handle_message(Peer *peer, DBusMessage *message) {
        const char *path = NULL,
                   *interface = NULL,
                   *member = NULL,
                   *error_name = NULL,
                   *destination = NULL,
                   /* *sender = NULL, XXX: verify? */
                   *signature = NULL;
        uint32_t reply_serial = 0, n_fds = 0;

        if (n_fds > message->n_fds)
                return -EBADMSG;
        while (n_fds < message->n_fds)
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
